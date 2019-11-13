package SRP::Command::check;
use Mojo::Base 'Mojolicious::Command';
use Mojo::mysql;
use Net::LDAP qw(LDAP_SUCCESS LDAP_INSUFFICIENT_ACCESS);
use Net::LDAP::Util qw(canonical_dn);

has description => 'Check and clean security groups';
has usage => "Usage: APPLICATION check\n";

sub run {
  my $self = shift;
  my $app = $self->app;

  $app->log->info('Check started '.localtime());
  # ldap operations
  my $ldap = Net::LDAP->new($app->config('ldapservers'), port => 389, timeout => 10);
  unless ($ldap) {
    $app->log->fatal("Ldap connection error. Create object failed. $@");
    exit 1;
  }
  my $mesg = $ldap->bind($app->config('ldapuser'), password => $app->config('ldappass'), version => 3);
  if ($mesg->code) {
    $app->log->fatal('Ldap bind error: '.$mesg->error);
    exit 1;
  }

  # group config
  my @sec_groups = map { { %$_ } } @{$app->config('sec_groups')}; # copy structure

  # load all group members into hash
  foreach my $sg (@sec_groups) {
    #say "Group: ".$sg->{dn};
    # search ldap for group members
    my $res = $ldap->search(base => $sg->{dn}, filter => '(objectClass=group)', scope => 'base', attrs => ['member']);
    if ($res->code) {
      $app->log->fatal('Ldap group search error: '.$res->error);
      $ldap->unbind;
      exit 1;
    }
    if ($res->count > 0) {
      my @member_list;
      # resolve dn-s to logins
      foreach my $m ($res->entry(0)->get_value('member')) {
        utf8::decode($m);
        my $res1 = $ldap->search(base => $m, filter => '(|(objectClass=person)(objectClass=group))', scope => 'base', attrs => ['sAMAccountName']);
        if ($res1->code) {
          $app->log->fatal('Ldap search error: '.$res1->error);
          $ldap->unbind;
          exit 1;
        }
        if ($res1->count > 0) {
          my $user_login = $res1->entry(0)->get_value('sAMAccountName');
          utf8::decode($user_login);
          #say "Member: ".canonical_dn($m).", Login: ".lc($user_login);
          push @member_list, { dn => canonical_dn($m), login => lc($user_login) }
        } else {
          $app->log->warning("User or group $m can not be found in active directory");
        }
      }# resolve members dn-s
      $sg->{members} = \@member_list;
    } else {
      $app->log->fatal("Ldap group $sg->{dn} is not found in active directory");
      $ldap->unbind;
      exit 1;
    }
  } #foreach my $sg

  # cleaning ---
  my $db_sec = $app->mysql_secraise->db;
  my $db_otrs = $app->mysql_tickets->db;
  my $rec = $db_sec->query("SELECT id, login, tn, priv_code FROM secraise");
  while (my $next = $rec->hash) {
    #say $app->dumper($next);
    my $delete_flag = 0;
    my $ttitle = 'н/д';
    if ($next->{tn}) {
      # lookup for ticket
      my $ticket_rec = $db_otrs->query("SELECT t.title, ts.type_id AS tstate_id \
      FROM ticket t \
      INNER JOIN ticket_state ts ON t.ticket_state_id = ts.id \
      WHERE t.tn = ?", $next->{tn}
      );
      if (my $v = $ticket_rec->array) {
        # ticket closed?
        if ($app->is_ticket_closed($v->[1])) {
          $ttitle = $v->[0] || 'н/д';
          $delete_flag = 1;
        }
      } else { # ticket not found
        $app->log->error("Ticket number $next->{tn} is not found for request id: ".$next->{id});
        $delete_flag = 1;
      }
      $ticket_rec->finish;
    } else { # empty ticket number
      $app->log->error('Empty ticket number for request id: '.$next->{id});
      $delete_flag = 1;
    }

    # delete request from table
    my $user_login = $next->{login};
    if ($delete_flag) {
      $app->log->info("Releasing request $next->{id} for user: $user_login, ticket: $next->{tn}, privilege: $next->{priv_code}.");
      my $r = $db_sec->query("DELETE FROM secraise WHERE id = ?", $next->{id});
      if ($r->affected_rows != 1) {
        $app->log->error("Secraise record hasn't been deleted.");
      }
      # add to secraise_log
      $app->dblog(login => $user_login, tn => $next->{tn}, title => $ttitle,
        priv_code => $next->{priv_code}, state_code => 2, reason => 'Закрытие заявки');
    } else {
      # (consistency) check corresponding membership in ldap group
      my $user_found_in_group;
      MEMBERLOOP1:
      foreach (@{$sec_groups[$next->{priv_code}]->{members}}) {
        if ($_->{login} eq $user_login) { $user_found_in_group = 1; last MEMBERLOOP1; }
      }
      unless ($user_found_in_group) {
        $app->log->error("Consistency check failure. User $user_login is not found in group $sec_groups[$next->{priv_code}]->{dn} as he should be.");
      }
    }
  } # loop all requests
  $rec->finish;

  # now the final check
  my $cur_priv = 0;
  foreach my $sg (@sec_groups) { #say "Group: ".$sg->{dn};
    foreach my $m (@{$sg->{members}}) { #say "Login: $m->{login}";
      # looking for at least one request exist
      $rec = $db_sec->query("SELECT COUNT(*) FROM secraise WHERE login = ? AND priv_code = ?", $m->{login}, $cur_priv);
      if (my $v = $rec->array) { #say $v->[0];
        # delete members having no requests
        if ($v->[0] == 0) {
          $app->log->info("Removing user $m->{login} from group $sg->{dn}");
          my $mesg = $ldap->modify($sg->{dn}, delete => { member => [$m->{dn}] });
          if ($mesg->code) {
            $app->log->error("Error removing user $m->{dn} from group $sg->{dn}, code: ".$mesg->code.', error: '.$mesg->error);
          }
        }
      } else {
        $app->log->fatal("A kind of database error occurs during final check $m->{login}, privilege $cur_priv.");
      }
      $rec->finish;
    }
    $cur_priv++;
  } #foreach my $sg

  $ldap->unbind;
  $ldap = undef;
  $app->log->debug('Check finished '.localtime());
  exit 0;
}

1;