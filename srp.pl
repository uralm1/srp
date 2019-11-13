#!/usr/bin/env perl
use Mojolicious::Lite;
use Mojo::mysql;
use Net::LDAP qw(LDAP_SUCCESS LDAP_INSUFFICIENT_ACCESS);
use Net::LDAP::Util qw(canonical_dn);
use POSIX qw(ceil);

# Documentation browser under "/perldoc"
#plugin 'PODRenderer';

#app->mode('production');
#app->log->level('info');
app->secrets(['fghbvrsdlfkgfjdj']);

# otrs ticket state types (translated 'ticket_state_type' table)
my %otrs_ticket_state_types = (
  1 => 'Новая', #new
  2 => 'Открыта', #open
  3 => 'Закрыта', #closed
  4 => 'Ожидает напоминания', #pending reminder
  5 => 'Ожидает автозакрытия', #pending auto
  6 => 'Удаленная', #removed
  7 => 'Объединенные', #merged
);
# otrs id for valid records, see 'valid' table
my $otrs_valid_id = 1;

# security log state codes
my %sec_state_codes = (
  0 => '', #no change
  1 => 'Предоставлено',
  2 => 'Отозвано',
  3 => 'Ошибка изменения!',
  4 => 'Запрещено!',
);

require 'srpchecker.pm';
require 'groupdump.pm';
push @{app->commands->namespaces}, 'SRP::Command';
require 'mpagenav.pm';
plugin 'SRP::Plugin::mpagenav';

plugin 'Config' => {file => 'secraise.conf'};
delete app->defaults->{config}; # safety - not to pass passwords to stashes

helper pdir => sub { return shift->config->{program_dir_url} };

helper mysql_tickets => sub {
  state $mysql_tickets = Mojo::mysql->new(shift->config->{tickets_db_conn});
};

helper mysql_secraise => sub {
  state $mysql_secraise = Mojo::mysql->new(shift->config->{sec_db_conn});
};

helper get_ticket_service => sub { shift;
  my $service = shift;
  return 'н/д' unless $service;
  $service =~ /(.*\S) *\[\S*\]$/;
  return ($1) ? $1:'н/д';
};

helper get_ticket_state => sub { shift;
  my $id = shift;
  return 'н/д' unless $id;
  my $s = $otrs_ticket_state_types{$id} || 'н/д';
  return $s; #tstate_name
};

helper is_ticket_closed => sub { shift;
  my $id = shift;
  return ($id == 3 || $id == 6 || $id == 7);
};

helper get_sec_state => sub { shift;
  my $id = shift;
  return $sec_state_codes{$id} || "н/д (код: $id)";
};

helper get_sec_priv => sub {
  shift;
  my $id = shift;
  my $sec_groups = app->config('sec_groups');
  my $sec_h = $sec_groups->[$id];
  return (defined($sec_h)) ? $sec_h->{priv} : "н/д (код: $id)";
};

helper dblog => sub {
  my $app = shift;
  my $logdata = {@_};
  for (qw(login priv_code state_code)) { die 'Parameter missing' unless defined($logdata->{$_}); }
  for (qw(login tn title)) { $logdata->{$_} = 'н/д' unless $logdata->{$_}; }
  $logdata->{reason} = 'По запросу пользователя' unless $logdata->{reason};
  my $r = $app->mysql_secraise->db->query("INSERT INTO secraise_log \
    (login, date, tn, title, priv_code, state_code, reason) VALUES (?, NOW(), ?, ?, ?, ?, ?)",
    $logdata->{login}, $logdata->{tn}, $logdata->{title}, $logdata->{priv_code}, $logdata->{state_code}, $logdata->{reason});
  if ($r->affected_rows != 1) {
    $app->log->error("Log record ($logdata->{login}, $logdata->{priv_code}, $logdata->{state_code}) hasn't been inserted.");
  }
};

helper exists_and_number => sub {
  my ($self, $v) = @_;
  unless (defined($v) && $v =~ /^\d+$/) {
    $self->render(template => 'err', err_msg => {});
    return 0;
  }
  return 1;
};

helper load_ticket_title_by_tn => sub {
  my ($self, $tn) = @_;
  my $ttitle;
  my $rec = $self->mysql_tickets->db->query("SELECT title FROM ticket WHERE tn = ?", $tn);
  if (my $next = $rec->array) {
    $ttitle = $next->[0];
  } else {
    $self->app->log->error("Ticket $tn is not found in otrs database");
    $ttitle = 'н/д';
  }
  $rec->finish;
  return $ttitle;
};

helper get_log_rowcount_by_login => sub {
  my ($self, $login) = @_;
  my $rec = $self->mysql_secraise->db->query("SELECT COUNT(*) FROM secraise_log WHERE login = ?", $login);
  my $lines_total = $rec->array->[0];
  $rec->finish;
  return $lines_total;
};

under sub {
  my $c = shift;

  $c->stash(remote_user => 'sorok'); ### FIXME DEBUG FIXME
  #$c->stash(remote_user => lc($c->req->env->{'REMOTE_USER'}));

  # authentication via simple login list
  #my $remote_user = $c->stash('remote_user');
  #return 1 if ($remote_user && app->config('allowed_users')->{$remote_user});
  # authentication via group
  my $group_list = $c->req->headers->header(app->config('allowed_group_header'));
  $group_list = 'Security_Raise_Project'; ### FIXME DEBUG FIXME
  my $group_name = app->config('allowed_group_name');
  return 1 if $group_list =~ /\b$group_name\b/;

  app->log->info('Authorization failure for '.$c->stash('remote_user'));
  $c->render(template => 'err', err_msg => {
    header => 'Доступ запрещен',
    text => 'Ваш уровень допуска не позволяет использовать данную программу.',
  });
  return undef;
};

#
# /rq?ticket=7262
#
get '/rq' => sub {
  my $c = shift;
  my $ticket_id = $c->param('ticket');
  return unless $c->exists_and_number($ticket_id);
  my $log_active_page = $c->param('p') || 1;
  return unless $c->exists_and_number($log_active_page);

  # load ticket data
  my ($db, $rec);
  $db = $c->mysql_tickets->db;
  $rec = $db->query("SELECT t.id, t.tn, t.title, \
DATE_FORMAT(t.create_time, '%e.%m.%Y %H:%i') AS tcreated, \
tt.name AS ttype, q.name AS queue, \
t.customer_user_id AS from_id, \
s.name AS service, ts.type_id AS tstate_id, tst.name AS tstate_name \
FROM ticket t \
INNER JOIN ticket_state ts ON t.ticket_state_id = ts.id \
INNER JOIN ticket_state_type tst ON ts.type_id = tst.id \
LEFT OUTER JOIN ticket_type tt ON t.type_id = tt.id \
LEFT OUTER JOIN queue q ON t.queue_id = q.id \
LEFT OUTER JOIN service s ON t.service_id = s.id \
WHERE t.id = ?", $ticket_id);

  my %ticket;
  my $customer_login;
  if (my $next = $rec->hash) {
    $ticket{id} = $next->{id};
    $ticket{tn} = $next->{tn};
    $ticket{title} = $next->{title} || 'н/д';
    $ticket{type} = $next->{ttype};
    $ticket{queue} = $next->{queue};
    $ticket{created} = $next->{tcreated} || 'н/д';
    $ticket{service} = $c->get_ticket_service($next->{service});
    my $tstate = $next->{tstate_id};
    $ticket{state} = $c->get_ticket_state($tstate);
    # in closed state we cannot open priviledges
    $ticket{closed} = $c->is_ticket_closed($tstate);
    $customer_login = $next->{from_id};
  } else {
    app->log->fatal("Ticket id $ticket_id is not found in otrs database");
    $c->render(template => 'err', err_msg => {});
    return;
  }
  $rec->finish;

  # ldap operations
  my $ldap = Net::LDAP->new(app->config('ldapservers'), port => 389, timeout => 10);
  unless ($ldap) {
    app->log->fatal("Ldap connection error. Create object failed. $@");
    $c->render(template => 'err', err_msg => {});
    return;
  }
  my $mesg = $ldap->bind(app->config('ldapuser'), password => app->config('ldappass'), version => 3);
  if ($mesg->code) {
    app->log->fatal('Ldap bind error: '.$mesg->error);
    $c->render(template => 'err', err_msg => {});
    return;
  }
  # search ldap for full user name, email, dn
  my ($user_login, $user_fio, $user_email, $user_dn);
  $user_login = $c->stash('remote_user');
  my $filter = "(&(objectClass=person)(sAMAccountName=$user_login))";
  my $res = $ldap->search(base => app->config('ldapbase'), filter => $filter, attrs => ['cn','mail','distinguishedName']);
  if ($res->code) {
    app->log->fatal('Ldap search error: '.$res->error);
    $ldap->unbind;
    $c->render(template => 'err', err_msg => {});
    return;
  }
  if ($res->count > 0) {
    my $entry = $res->entry(0);
    $user_fio = $entry->get_value('cn') || "Пользователь: $user_login";
    $user_dn = $entry->get_value('distinguishedName');
    $user_email = $entry->get_value('mail') || '';
    utf8::decode($user_fio);
    utf8::decode($user_email);
    utf8::decode($user_dn);
  } else {
    app->log->fatal("Login $user_login is not found in active directory");
    $ldap->unbind;
    $c->render(template => 'err', err_msg => {});
    return;
  }
  # search ldap for ticket customer
  if ($customer_login) {
    $filter = "(&(objectClass=person)(sAMAccountName=$customer_login))";
    $res = $ldap->search(base => app->config('ldapbase'), filter => $filter, attrs => ['cn']);
    if ($res->code) {
      app->log->fatal('Ldap search error: '.$res->error);
      $ldap->unbind;
      $c->render(template => 'err', err_msg => { });
      return;
    }
    my $customer_fio;
    if ($res->count > 0) {
      my $entry = $res->entry(0);
      $customer_fio = $entry->get_value('cn') || $customer_login;
      utf8::decode($customer_fio);
    } else {
      app->log->info("Customer login $customer_login is not found in active directory, checking db backend");
      # check db backend
      $rec = $db->query("SELECT CONCAT_WS(' ', last_name, first_name) \
FROM customer_user \
WHERE login = ? AND valid_id = $otrs_valid_id", $customer_login);
      if (my $next = $rec->array) {
        $customer_fio = $next->[0];
      } else {
        app->log->info("Customer login $customer_login is not found in ldap and db, using login value instead");
        $customer_fio = $customer_login;
      }
      $rec->finish;
    }
    $ticket{from} = $customer_fio;
  } else {
    $ticket{from} = 'неизвестно';
  }

  # group config
  my @sec_groups = map { { %$_ } } @{app->config('sec_groups')}; # copy structure

  # group operation
  my $db_sec = $c->mysql_secraise->db;
  my $secbyticket_rec = $db_sec->query("SELECT priv_code FROM secraise WHERE login = ? AND tn = ?", $user_login, $ticket{tn});
  while (my $next = $secbyticket_rec->array) {
    $sec_groups[$next->[0]]->{ticketmember} = 1;
  }
  $secbyticket_rec->finish;

  my $cur_priv = 0;
  $user_dn = canonical_dn($user_dn);
  foreach my $sg (@sec_groups) {
    #say "Group: ".$sg->{dn};

    # search ldap for group members
    $res = $ldap->search(base => $sg->{dn}, filter => '(objectClass=group)', scope => 'base', attrs => ['member']);
    if ($res->code) {
      app->log->fatal('Ldap group search error: '.$res->error);
      $ldap->unbind;
      $c->render(template => 'err', err_msg => { });
      return;
    }
    if ($res->count > 0) {
      my $entry = $res->entry(0);
      my @v = $entry->get_value('member');
    GROUPMEMBER:
      foreach my $m (@v) {
        #say "Member: ".canonical_dn($m);
        utf8::decode($m);
        if (canonical_dn($m) eq $user_dn) {
          $sg->{groupmember} = 1; #say "Found in group!";
          last GROUPMEMBER;
        }
      }
    } else {
      app->log->fatal("Ldap group $sg->{dn} is not found in active directory");
      $ldap->unbind;
      $c->render(template => 'err', err_msg => { });
      return;
    }

    # and check if there other tickets with this privilege granted
    my $other_tickets_rec = $db_sec->query("SELECT tn FROM secraise WHERE login = ? AND tn != ? AND priv_code = ?", $user_login, $ticket{tn}, $cur_priv);
    if ($other_tickets_rec->rows > 0) {
      $sg->{otherticketmember} = 1;
    }
    $other_tickets_rec->finish;
    $cur_priv++;
  } #foreach my $sg

  $ldap->unbind;
  $ldap = undef;

  # paginated log
  my $lines_on_page = app->config('log_lines_on_user_page');
  my $num_pages = ceil($c->get_log_rowcount_by_login($user_login) / $lines_on_page);
  #say "np:$num_pages, lop:$lines_on_page, lap:$log_active_page";
  return $c->render(template => 'err', err_msg => {}) if ($log_active_page < 1 || ($num_pages > 0 && $log_active_page > $num_pages));

  my $log_rec = $db_sec->query("SELECT DATE_FORMAT(date, '%e.%m.%Y %H:%i') AS fdate, \
    tn, title, priv_code, state_code, reason \
    FROM secraise_log \
    WHERE login = ? \
    ORDER BY date DESC LIMIT ? OFFSET ?", $user_login, $lines_on_page, ($log_active_page - 1)*$lines_on_page);

  $c->render(template => 'request',
    user_line => $user_fio.', '.$user_email,
    ticket_rec => \%ticket,
    sec_groups => \@sec_groups,
    log_num_pages => $num_pages,
    log_active_page => $log_active_page,
    log_rec => $log_rec,
  );
};


post '/apply' => sub {
  my $c = shift;
  # get ticket id and number from hidden parameter
  my $ticket_id = $c->req->body_params->param("tid");
  my $ticket_num = $c->req->body_params->param("tn");
  my $ticket_title = $c->req->body_params->param("title") || 'н/д';
  return unless($c->exists_and_number($ticket_id) && $c->exists_and_number($ticket_num));

  # ldap operations
  my $ldap = Net::LDAP->new(app->config('ldapservers'), port => 389, timeout => 10);
  unless ($ldap) {
    app->log->fatal("Ldap connection error. Create object failed. $@");
    $c->render(template => 'err', err_msg => {});
    return;
  }
  my $mesg = $ldap->bind(app->config('ldapuser'), password => app->config('ldappass'), version => 3);
  if ($mesg->code) {
    app->log->fatal('Ldap bind error: '.$mesg->error);
    $c->render(template => 'err', err_msg => {});
    return;
  }

  # search ldap for full user name, email, dn
  my ($user_login, $user_fio, $user_email, $user_dn);
  $user_login = $c->stash('remote_user');
  my $filter = "(&(objectClass=person)(sAMAccountName=$user_login))";
  my $res = $ldap->search(base => app->config('ldapbase'), filter => $filter, attrs => ['cn','mail','distinguishedName']);
  if ($res->code) {
    app->log->fatal('Ldap search error: '.$res->error);
    $ldap->unbind;
    $c->render(template => 'err', err_msg => {});
    return;
  }
  if ($res->count > 0) {
    my $entry = $res->entry(0);
    $user_fio = $entry->get_value('cn') || "Пользователь: $user_login";
    $user_dn = $entry->get_value('distinguishedName');
    $user_email = $entry->get_value('mail') || '';
    utf8::decode($user_fio);
    utf8::decode($user_email);
    utf8::decode($user_dn);
  } else {
    app->log->fatal("Login $user_login is not found in active directory");
    $ldap->unbind;
    $c->render(template => 'err', err_msg => {});
    return;
  }

  # group config
  my @sec_groups = map { { %$_ } } @{app->config('sec_groups')}; # copy structure

  my $db_sec = $c->mysql_secraise->db;
  my $secbyticket_rec = $db_sec->query("SELECT priv_code FROM secraise WHERE login = ? AND tn = ?", $user_login, $ticket_num);
  while (my $next = $secbyticket_rec->array) {
    $sec_groups[$next->[0]]->{ticketmember} = 1;
  }
  $secbyticket_rec->finish;

  # group operation
  my $cur_priv = 0;
  my @res_arr;
  $user_dn = canonical_dn($user_dn);
  foreach my $sg (@sec_groups) {
    #say "Group: ".$sg->{dn};

    # search ldap for group members
    $res = $ldap->search(base => $sg->{dn}, filter => '(objectClass=group)', scope => 'base', attrs => ['member']);
    if ($res->code) {
      app->log->fatal('Ldap group search error: '.$res->error);
      $ldap->unbind;
      $c->render(template => 'err', err_msg => { });
      return;
    }
    if ($res->count > 0) {
      my $entry = $res->entry(0);
      my @v = $entry->get_value('member');
      GROUPMEMBER:
      foreach my $m (@v) {
        #say "Member: ".canonical_dn($m);
        utf8::decode($m);
        if (canonical_dn($m) eq $user_dn) {
          $sg->{groupmember} = 1; #say "Found in group!";
          last GROUPMEMBER;
        }
      }
    } else {
      app->log->fatal("Ldap group $sg->{dn} is not found in active directory");
      $ldap->unbind;
      $c->render(template => 'err', err_msg => { });
      return;
    }

    # now add or remove user from group
    $res_arr[$cur_priv] = 0; # no change
    my $p = $c->req->body_params->param("priv$cur_priv");
    if ($p && !$sg->{ticketmember}) {
      # add user privilege
      app->log->debug("Adding user $user_login privilege code $cur_priv");
      my $mesg;
      unless ($sg->{groupmember}) {
        # add user_dn to group
        app->log->debug("Adding user $user_dn to group $sg->{dn}");
        $mesg = $ldap->modify($sg->{dn}, add => { member => [ $user_dn ] });
      }
      if (!$sg->{groupmember} && $mesg->code) {
        app->log->error("Error adding user to group, code: ".$mesg->code.', error: '.$mesg->error);
        if ($mesg->code == LDAP_INSUFFICIENT_ACCESS) {
          $res_arr[$cur_priv] = 4; # forbidden
          # add to secraise_log
          app->dblog(login => $user_login, tn => $ticket_num, title => $ticket_title,
            priv_code => $cur_priv, state_code => 4, reason => 'Выдача запрещена');
        } else {
          $res_arr[$cur_priv] = 3; # error
        }
      } else {
        # success
        $res_arr[$cur_priv] = 1; # granted
        # add to secraise table
        my $r = $db_sec->query("INSERT INTO secraise (login, tn, priv_code) VALUES (?, ?, ?)", $user_login, $ticket_num, $cur_priv);
        if ($r->affected_rows != 1) {
          app->log->error("Secraise record hasn't been inserted.");
          $res_arr[$cur_priv] = 3; # error
        }
        # add to secraise_log
        app->dblog(login => $user_login, tn => $ticket_num, title => $ticket_title,
          priv_code => $cur_priv, state_code => 1);
      }
    } elsif (!$p && $sg->{ticketmember}) {
      # remove user privilege
      app->log->debug("Removing user $user_login privilege code $cur_priv");
      # first check if there other tickets with this privilege granted
      my $other_tickets_rec = $db_sec->query("SELECT COUNT(*) FROM secraise WHERE login = ? AND tn != ? AND priv_code = ?", $user_login, $ticket_num, $cur_priv);
      if (my $v = $other_tickets_rec->array) {
        my $mesg;
        if ($v->[0] == 0) {
          # remove user_dn from group
          app->log->debug("Removing user $user_dn from group $sg->{dn}");
          $mesg = $ldap->modify($sg->{dn}, delete => { member => [$user_dn] });
        }
        if ($v->[0] == 0 && $mesg->code) {
          app->log->error("Error removing user from group, code: ".$mesg->code.', error: '.$mesg->error);
          if ($mesg->code == LDAP_INSUFFICIENT_ACCESS) {
            $res_arr[$cur_priv] = 4; # forbidden
            # add to secraise_log
            app->dblog(login => $user_login, tn => $ticket_num, title => $ticket_title,
              priv_code => $cur_priv, state_code => 4, reason => 'Отзыв запрещен');
          } else {
            $res_arr[$cur_priv] = 3; # error
          }
        } else {
          # success
          $res_arr[$cur_priv] = 2; # revoked
          # delete from secraise table
          my $r = $db_sec->query("DELETE FROM secraise WHERE login = ? AND tn = ? AND priv_code = ?", $user_login, $ticket_num, $cur_priv);
          if ($r->affected_rows != 1) {
            app->log->error("Secraise record hasn't been deleted.");
            $res_arr[$cur_priv] = 3; # error
          }
          # add to secraise_log
          app->dblog(login => $user_login, tn => $ticket_num, title => $ticket_title,
            priv_code => $cur_priv, state_code => 2);
        }
      } else {
        app->log->fatal("A kind of database error occurs during remove user $user_login, privilege $cur_priv.");
      }
      $other_tickets_rec->finish;
    }
    $cur_priv++;
  } #foreach my $sg

  $ldap->unbind;
  $ldap = undef;

  $c->flash(res => \@res_arr);
  $c->redirect_to($c->url_for('rq')->query(ticket => $ticket_id));
  #$c->render(template => 'apply');
};


get '/' => sub {
  my $c = shift;
  my $log_active_page = $c->param('p') || 1;
  return unless $c->exists_and_number($log_active_page);

  # ldap operations
  my $ldap = Net::LDAP->new(app->config('ldapservers'), port => 389, timeout => 10);
  unless ($ldap) {
    app->log->fatal("Ldap connection error. Create object failed. $@");
    $c->render(template => 'err', err_msg => {});
    return;
  }
  my $mesg = $ldap->bind(app->config('ldapuser'), password => app->config('ldappass'), version => 3);
  if ($mesg->code) {
    app->log->fatal('Ldap bind error: '.$mesg->error);
    $c->render(template => 'err', err_msg => {});
    return;
  }
  # search ldap for full user name, email, dn
  my ($user_login, $user_fio, $user_email, $user_dn);
  $user_login = $c->stash('remote_user');
  my $filter = "(&(objectClass=person)(sAMAccountName=$user_login))";
  my $res = $ldap->search(base => app->config('ldapbase'), filter => $filter, attrs => ['cn','mail','distinguishedName']);
  if ($res->code) {
    app->log->fatal('Ldap search error: '.$res->error);
    $ldap->unbind;
    $c->render(template => 'err', err_msg => {});
    return;
  }
  if ($res->count > 0) {
    my $entry = $res->entry(0);
    $user_fio = $entry->get_value('cn') || "Пользователь: $user_login";
    $user_dn = $entry->get_value('distinguishedName');
    $user_email = $entry->get_value('mail') || '';
    utf8::decode($user_fio);
    utf8::decode($user_email);
    utf8::decode($user_dn);
  } else {
    app->log->fatal("Login $user_login is not found in active directory");
    $ldap->unbind;
    $c->render(template => 'err', err_msg => {});
    return;
  }

  # group config
  my @sec_groups = map { { %$_ } } @{app->config('sec_groups')}; # copy structure

  my $db_sec = $c->mysql_secraise->db;
  # group operation
  my $cur_priv = 0;
  $user_dn = canonical_dn($user_dn);
  foreach my $sg (@sec_groups) {
    #say "Group: ".$sg->{dn};

    # search ldap for group members
    $res = $ldap->search(base => $sg->{dn}, filter => '(objectClass=group)', scope => 'base', attrs => ['member']);
    if ($res->code) {
      app->log->fatal('Ldap group search error: '.$res->error);
      $ldap->unbind;
      $c->render(template => 'err', err_msg => { });
      return;
    }
    if ($res->count > 0) {
      my $entry = $res->entry(0);
      my @v = $entry->get_value('member');
      GROUPMEMBER:
      foreach my $m (@v) {
        #say "Member: ".canonical_dn($m);
        utf8::decode($m);
        if (canonical_dn($m) eq $user_dn) {
          $sg->{groupmember} = 1; #say "Found in group!";
          last GROUPMEMBER;
        }
      }
    } else {
      app->log->fatal("Ldap group $sg->{dn} is not found in active directory");
      $ldap->unbind;
      $c->render(template => 'err', err_msg => { });
      return;
    }
    # count number if tickets linked
    my $tickets_rec = $db_sec->query("SELECT COUNT(*) FROM secraise WHERE login = ? AND priv_code = ?", $user_login, $cur_priv);
    $sg->{ticketcount} = $tickets_rec->array->[0];
    $tickets_rec->finish;

    $cur_priv++;
  } #foreach my $sg

  $ldap->unbind;
  $ldap = undef;

  # paginated log
  my $lines_on_page = app->config('log_lines_on_user_page');
  my $num_pages = ceil($c->get_log_rowcount_by_login($user_login) / $lines_on_page);
  #say "np:$num_pages, lop:$lines_on_page, lap:$log_active_page";
  return $c->render(template => 'err', err_msg => {}) if ($log_active_page < 1 || ($num_pages > 0 && $log_active_page > $num_pages));

  my $log_rec = $db_sec->query("SELECT DATE_FORMAT(date, '%e.%m.%Y %H:%i') AS fdate, \
    tn, title, priv_code, state_code, reason \
    FROM secraise_log \
    WHERE login = ? \
    ORDER BY date DESC LIMIT ? OFFSET ?", $user_login, $lines_on_page, ($log_active_page - 1)*$lines_on_page);

  $c->render(template => 'index',
    user_line => $user_fio.', '.$user_email,
    sec_groups => \@sec_groups,
    log_num_pages => $num_pages,
    log_active_page => $log_active_page,
    log_rec => $log_rec,
  );
} => 'index';


get '/confirm' => sub {
  my $c = shift;
  my $priv = $c->param('priv');
  my $sg = app->config('sec_groups');
  return unless $c->exists_and_number($priv);
  return $c->render(template => 'err', err_msg => {}) unless $sg->[$priv];

  $c->stash(priv => $priv, priv_title => $sg->[$priv]->{title}, priv_comment => $sg->[$priv]->{comment});
  $c->render(template => 'confirm');
};


post '/rev' => sub {
  my $c = shift;
  my $sg = app->config('sec_groups');
  my $priv = $c->req->body_params->param('priv');
  return unless $c->exists_and_number($priv);
  return $c->render(template => 'err', err_msg => {}) unless $sg->[$priv];

  # ldap operations
  my $ldap = Net::LDAP->new(app->config('ldapservers'), port => 389, timeout => 10);
  unless ($ldap) {
    app->log->fatal("Ldap connection error. Create object failed. $@");
    return $c->render(template => 'err', err_msg => {});
  }
  my $mesg = $ldap->bind(app->config('ldapuser'), password => app->config('ldappass'), version => 3);
  if ($mesg->code) {
    app->log->fatal('Ldap bind error: '.$mesg->error);
    return $c->render(template => 'err', err_msg => {});
  }
  # search ldap for full user name, email, dn
  my ($user_login, $user_fio, $user_email, $user_dn);
  $user_login = $c->stash('remote_user');
  my $filter = "(&(objectClass=person)(sAMAccountName=$user_login))";
  my $res = $ldap->search(base => app->config('ldapbase'), filter => $filter, attrs => ['cn','mail','distinguishedName']);
  if ($res->code) {
    app->log->fatal('Ldap search error: '.$res->error);
    $ldap->unbind;
    $c->render(template => 'err', err_msg => {});
    return;
  }
  if ($res->count > 0) {
    my $entry = $res->entry(0);
    $user_fio = $entry->get_value('cn') || "Пользователь: $user_login";
    $user_dn = $entry->get_value('distinguishedName');
    $user_email = $entry->get_value('mail') || '';
    utf8::decode($user_fio);
    utf8::decode($user_email);
    utf8::decode($user_dn);
  } else {
    app->log->fatal("Login $user_login is not found in active directory");
    $ldap->unbind;
    $c->render(template => 'err', err_msg => {});
    return;
  }

  # remove user_dn from group
  app->log->debug("Removing user $user_dn from group $sg->[$priv]->{dn}");
  $mesg = $ldap->modify($sg->[$priv]->{dn}, delete => { member => [$user_dn] });
  if ($mesg->code) {
    app->log->error("Error removing user from group, code: ".$mesg->code.', error: '.$mesg->error);
  } else {
    # success
  }

  $ldap->unbind;
  $ldap = undef;

  # get all tickets with this privilege
  my $db_sec = $c->mysql_secraise->db;
  my $tickets_rec = $db_sec->query("SELECT tn FROM secraise WHERE login = ? AND priv_code = ?", $user_login, $priv);
  my $tc = $tickets_rec->arrays;
  $tickets_rec->finish;

  foreach (@$tc) {
    my $tn = $_->[0]; #ticket number

    # delete from secraise table
    my $r = $db_sec->query("DELETE FROM secraise WHERE login = ? AND tn = ? AND priv_code = ?", $user_login, $tn, $priv);
    if ($r->affected_rows != 1) {
      app->log->error("Secraise record for ticket $tn hasn't been deleted.");
    } else {
      # success
      # add to secraise_log
      app->dblog(login => $user_login, tn => $tn, title => $c->load_ticket_title_by_tn($tn), priv_code => $priv, state_code => 2);
    }
  } # for each ticket

  $c->flash(oper => 'Отзыв полномочия выполнен');
  $c->redirect_to($c->url_for('index'));
};


get '/admin' => sub {
  my $c = shift;
  my $log_active_page = $c->param('p') || 1;
  return unless $c->exists_and_number($log_active_page);

  # authorization via hash
  my $remote_user = $c->stash('remote_user');
  unless ($remote_user && app->config('allowed_admins')->{$remote_user}) {
    app->log->info('Admin authorization failure for '.$remote_user);
    return $c->render(template => 'err', err_msg => {
      header => 'Доступ запрещен',
      text => 'Ваш уровень допуска не позволяет использовать данную программу.',
    });
  }

  my $db_sec = $c->mysql_secraise->db;
  my $sec_rec = $db_sec->query("SELECT login, tn, priv_code FROM secraise ORDER BY login ASC");

  # paginated log
  my $lines_on_page = app->config('log_lines_on_admin_page');
  my $log_rec = $db_sec->query("SELECT COUNT(*) FROM secraise_log");
  my $lines_total = $log_rec->array->[0];
  $log_rec->finish;
  my $num_pages = ceil($lines_total / $lines_on_page);
  #say "lt:$lines_total, np:$num_pages, lop:$lines_on_page, lap:$log_active_page";
  return $c->render(template => 'err', err_msg => {}) if ($log_active_page < 1 || ($num_pages > 0 && $log_active_page > $num_pages));

  $log_rec = $db_sec->query("SELECT DATE_FORMAT(date, '%e.%m.%Y %H:%i') AS fdate, \
    login, tn, title, priv_code, state_code, reason \
    FROM secraise_log \
    ORDER BY date DESC LIMIT ? OFFSET ?", $lines_on_page, ($log_active_page - 1)*$lines_on_page);

  $c->render(template => 'admin',
    sec_rec => $sec_rec,
    log_num_pages => $num_pages,
    log_active_page => $log_active_page,
    log_rec => $log_rec,
  );
};



get '/err' => sub {
  my $c = shift;
  $c->render(template => 'err', err_msg => {
    header => 'Заголовок ошибки',
    text => 'Содержание сообщения об ошибке',
    btn_text => 'Текст на кнопке',
    btn_url => 'https://faq.uwc.ufanet.ru',
  });
};


app->start;


__DATA__

@@ request.html.ep
% layout 'default';
% my $res = flash 'res';
% if ($res) {
%   content_with done_toast => begin
<script>$(document).ready(function(){Materialize.toast('Запрос полномочий выполнен', 2500)});</script>
%   end
% }
<div class="scont">
<div class="section light">
  <h5 class="header"><%== $user_line %></h5>
  % if ($ticket_rec->{closed}) {
  <p>по завершенному заданию:</p>
  % } else {
  <p>для выполнения задания:</p>
  % }
  <blockquote class="sticket">
    <b>Заявка №<%= $ticket_rec->{tn} %></b> — <%= $ticket_rec->{title} %>.<br>
    <b>Тип:</b> <%= $ticket_rec->{type} %><br>
    <b>Очередь:</b> <%= $ticket_rec->{queue} %><br>
    <b>От:</b> <%= $ticket_rec->{from} %><br>
    <b>Создана:</b> <%= $ticket_rec->{created} %><br>
    <b>Сервис:</b> <%= $ticket_rec->{service} %><br>
    <b>Состояние:</b> <%= $ticket_rec->{state} %>
  </blockquote>
  % if ($ticket_rec->{closed}) {
  <p>Задание завершено, запрос полномочий не допускается.<br>Вы можете отозвать следующие полномочия:</p>
  % } else {
  <p>Вы можете запросить или отозвать следующие полномочия:</p>
  % }
%= form_for apply => (method => 'POST') => begin
%= hidden_field tid => $ticket_rec->{id}
%= hidden_field tn => $ticket_rec->{tn}
%= hidden_field title => $ticket_rec->{title}
    <ul class="collection">
% my $cnt = 0;
% foreach (@{$sec_groups}) {
      <li class="collection-item">
        <input type="checkbox" name="<%== "priv$cnt" %>" value="on" id="<%== "priv$cnt" %>" <%== $_->{ticketmember}?'checked="checked"':'' %>  <%== ($ticket_rec->{closed} && !$_->{ticketmember})?'disabled="disabled"':'' %>/>
        <label class="slabel" for="<%== "priv$cnt" %>">
        % if ($res && ref($res) eq 'ARRAY' && $res->[$cnt] != 0) {
          <span class="result<%= $res->[$cnt] %>"><%= get_sec_state($res->[$cnt]) %></span>
        % }
          <%= $_->{title} %>
          <div class="slabel-note"><%= $_->{comment} %></div>
        </label>
        % if ($_->{groupmember} && $_->{otherticketmember}) {
        <i class="secondary-content material-icons orange-text tooltipped" data-position="left" data-delay="50" data-tooltip="Внимание! Полномочие уже предоставлено Вам в рамках другой заявки">warning</i>
        % }
      </li>
%   $cnt++;
% }
    </ul>

    <button class="btn waves-effect waves-light orange" type="submit">Изменить права</button>
    % my $uu = url_for(config 'otrs_url')->query(Action => 'AgentTicketZoom', TicketID => $ticket_rec->{id});
    <a class="btn waves-effect waves-light" href="<%== $uu %>">Вернуться к заявке</a>
% end
</div>

<div class="section light">
  <h5 class="header light">Внимание!</h5>
  <p>Работая с повышенными полномочиями, уделяйте пристальное внимание правилам безопасной работы и
  <a href="https://faq.uwc.ufanet.ru/doku.php?id=antivirus:recomend">антивирусной защите</a>.</p>
  <p>Для активации полномочий на локальном компьютере Вам необходимо завершить Ваш текущий сеанс работы в системе (выполнить "Выход из системы") и повторно войти в систему со своим логином и паролем.</p>
  <p>Полученные полномочия будут <b>автоматически</b> отозваны после закрытия заявки.</p>
</div>

<div class="section light">
<h5 class="header light" id="log">Перечень последних запросов</h5>
<table class="striped">
  <thead>
    <tr>
      <th>Дата,время</th>
      <th>Полномочие</th>
      <th>Состояние</th>
      <th>Заявка</th>
    </tr>
  </thead>
  <tbody>
    % my $cnt = 0;
    % while (my $next = $log_rec->hash) {
    <tr>
      <td><%= $next->{fdate}||'н/д' %></td>
      <td><%= get_sec_priv($next->{priv_code}) %></td>
      <td><%= get_sec_state($next->{state_code})." ($next->{reason})" %></td>
      <td><%= "$next->{tn} - $next->{title}" %></td>
    </tr>
    % $cnt++;
    % }
    % unless ($cnt) {
    <tr><td colspan="4">Запросы не найдены</td></tr>
    % }
  </tbody>
</table>
  %= m_page_nav($log_active_page, $log_num_pages, {round=>3, outer=>1, start=>1, class=>'center-align', param=>'p', query=>'#log'});
</div>
</div>


@@ index.html.ep
% layout 'default';
% my $toast_msg = flash 'oper';
% if ($toast_msg) {
%   content_with done_toast => begin
<script>$(document).ready(function(){Materialize.toast('<%= $toast_msg %>', 2500)});</script>
%   end
% }
<div class="scont">
<div class="section light">
  <h5 class="header"><%== $user_line %></h5>
  <p>Перечень Ваших текущих полномочий.<br>Получить или отозвать необходимые полномочия можно через <a href="<%== config 'otrs_url' %>">систему поддержки пользователей</a>.
  Для этого необходимо создать новую или открыть существующую заявку по Вашей работе и выбрать опцию &quot;Запросить полномочия&quot; в меню действий с заявкой.</p>
  <table class="bordered">
    <thead>
      <tr>
        <th></th>
        <th>Полномочие</th>
        <th>Состояние</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      % my $cnt = 0;
      % foreach (@{$sec_groups}) {
      <tr>
        <td><i class="material-icons"><%= $_->{groupmember}?'done':'not_interested' %></i></td>
        <td><div class="slabel"><%= $_->{title} %><div class="slabel-note"><%= $_->{comment} %></div></div></td>
        <td class="result1"><%= $_->{groupmember}?"ПРЕДОСТАВЛЕНО ($_->{ticketcount})":'ОТСУТСТВУЕТ' %></td>
        <td><a class="btn-flat waves-effect waves-light<%= $_->{groupmember}?'':' disabled' %>" href="<%== url_for('confirm')->query(priv => $cnt) %>">Отозвать...</a></td>
      </tr>
      % $cnt++;
      % }
    </tbody>
  </table>
  <p><a class="btn waves-effect waves-light orange" href="<%== config 'otrs_url' %>">Перейти в систему поддержки для запроса полномочий</a></p>
</div>

<div class="section light">
<h5 class="header light" id="log">Перечень последних запросов</h5>
<table class="striped">
  <thead>
    <tr>
      <th>Дата,время</th>
      <th>Полномочие</th>
      <th>Состояние</th>
      <th>Заявка</th>
    </tr>
  </thead>
  <tbody>
    % $cnt = 0;
    % while (my $next = $log_rec->hash) {
    <tr>
      <td><%= $next->{fdate}||'н/д' %></td>
      <td><%= get_sec_priv($next->{priv_code}) %></td>
      <td><%= get_sec_state($next->{state_code})." ($next->{reason})" %></td>
      <td><%= "$next->{tn} - $next->{title}" %></td>
    </tr>
    % $cnt++;
    % }
    % unless ($cnt) {
      <tr><td colspan="4">Запросы не найдены</td></tr>
    % }
  </tbody>
</table>
  %= m_page_nav($log_active_page, $log_num_pages, {round=>3, outer=>1, start=>1, class=>'center-align', param=>'p', query=>'#log'});
</div>
</div>


@@ apply.html.ep
% layout 'default';
<div class="section">
<div class="row center">
  <div class="col s10 offset-s1 m8 offset-m2 l6 offset-l3">
    <div class="progress"><div class="indeterminate"></div></div>
    <p>Выполнение операции</p>
  </div>
</div>
</div>


@@ confirm.html.ep
% layout 'default';
%= form_for rev => (method => 'POST') => begin
<div class="scont">
<div class="section light">
  <h5 class="header">Подтверждение снятия полномочий</h4>
  <p>Вы действительно хотите отозвать полномочие:</p>
  <blockquote class="sticket slabel">
    <b><%= $priv_title %></b>
    <div class="slabel-note"><%= $priv_comment %></div>
  </blockquote>
  <p>из всех рабочих заявок, в которых оно Вам было предоставлено?</p>
</div>

%= hidden_field priv => $priv
<div class="section light">
  <button class="btn waves-effect waves-light orange" type="submit">Снять полномочие</button>
  <a class="btn waves-effect waves-light" href="<%= url_for 'index' %>">Отмена</a>
</div>
</div>
% end


@@ admin.html.ep
% layout 'default';
<div class="scont">
<div class="section light">
  <h4 class="header">Администрирование</h4>
  <h5 class="header">Выданные полномочия</h5>
  <table class="striped">
    <thead>
      <tr>
        <th></th>
        <th>Логин</th>
        <th>Полномочие</th>
        <th>Заявка</th>
      </tr>
    </thead>
    <tbody>
      % my $cnt = 1;
      % while (my $next = $sec_rec->hash) {
      <tr>
        <td><%= $cnt %></td>
        <td><%= $next->{login} %></td>
        <td><%= get_sec_priv($next->{priv_code}) %></td>
        <td><%= $next->{tn}.' - '.load_ticket_title_by_tn($next->{tn}) %></td>
      </tr>
      % $cnt++;
      % }
      % unless ($cnt) {
      <tr><td colspan="4">Полномочия не выданы</td></tr>
      % }
    </tbody>
  </table>

</div>
<div class="section light">
  <h5 class="header" id="log">Лог запросов</h5>
  <table class="striped">
    <thead>
      <tr>
        <th>Дата,время</th>
        <th>Логин</th>
        <th>Полномочие</th>
        <th>Состояние</th>
        <th>Заявка</th>
      </tr>
    </thead>
    <tbody>
      % $cnt = 0;
      % while (my $next = $log_rec->hash) {
      <tr>
        <td><%= $next->{fdate}||'н/д' %></td>
        <td><%= $next->{login}||'н/д' %></td>
        <td><%= get_sec_priv($next->{priv_code}) %></td>
        <td><%= get_sec_state($next->{state_code})." ($next->{reason})" %></td>
        <td><%= "$next->{tn} - $next->{title}" %></td>
      </tr>
      % $cnt++;
      % }
      % unless ($cnt) {
      <tr><td colspan="4">Запросы не найдены</td></tr>
      % }
    </tbody>
  </table>
  %= m_page_nav($log_active_page, $log_num_pages, {round=>3, outer=>1, start=>1, class=>'center-align', param=>'p', query=>'#log'});
</div>
</div>



@@ err.html.ep
% layout 'default';
<div class="section">
% my $e_header = 'Непредвиденная ошибка';
% my $e_text = 'К сожалению, в процессе загрузки произошла непредвиденная ошибка. Попробуйте обратиться позднее.';
% my $e_btn_text = 'Вернуться';
% my $t = stash 'err_msg';
% if ($t) {
%   $t->{header} = $e_header unless $t->{header};
%   $t->{text} = $e_text unless $t->{text};
%   $t->{btn_text} = $e_btn_text unless $t->{btn_text};
% } else {
%   $t = { header => $e_header, text => $e_text, btn_text => $e_btn_text };
% }
  <h4 class="header center"><%== $t->{header} %></h4>
  <div class="row center">
    <p class="col s12 light"><%== $t->{text} %></p>
  </div>
  <div class="row center">
% if ($t->{btn_url}) {
    <a href="<%== $t->{btn_url} %>" class="btn waves-effect waves-light orange"><%= $t->{btn_text} %></a>
% } else {
    <input class="btn waves-effect waves-light orange" type="button" value="<%= $t->{btn_text} %>" onclick="window.history.back()">
% }
  </div>
</div>


@@ layouts/default.html.ep
<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8"/>
  <meta http-equiv="X-UA-Compatible" content="IE=Edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=1.0">
  <title>Запрос доступа</title>
  <link rel="shortcut icon" href="<%== pdir %>/img/favicon.png">
  <!--link rel="stylesheet" href="<%== pdir %>/css/fonts-roboto.css"-->
  <link rel="stylesheet" href="<%== pdir %>/css/materialize.min.css">
  <link rel="stylesheet" href="<%== pdir %>/css/material-icons.css">
  <link rel="stylesheet" href="<%== pdir %>/css/styles.css">
</head>
<body>
  <nav class="white-text brown" role="navigation">
    <div class="nav-wrapper scont">
      <h4 class="brand-logo">Безопасность - Запрос полномочий</h5>
      <ul class="right hide-on-med-and-down">
        <li><a href="<%== config 'help_url' %>" target="_blank"><i class="material-icons">help</i></a></li>
      </ul>
    </div>
  </nav>
  <!--[if lte IE 9]>
    <div class="section"><div class="container"><div class="card-panel red">
      <b class="white-text">ВНИМАНИЕ! Вы используете устаревшую версию браузера Интернет. Многие элементы страницы будут отображены некорректно. Обновите версию Вашего браузера!</b>
    </div></div></div>
  <![endif]-->
<%= content %>
  <footer class="page-footer brown">
    <div class="footer-copyright">
      <div class="scont">
        <span title="Автор: Урал Хасанов, 2017">Группа сетевого администрирования</span>
        <span> &#x00b7 МУП "Уфаводоканал"</span>
        <a class="right brown-text text-lighten-4" href="<%== config 'faq_url' %>" target="_blank">Часто задаваемые вопросы (FAQ)</a>
      </div>
    </div>
  </footer>
  <script src="<%== pdir %>/js/jquery-3.1.1.min.js"></script>
  <script src="<%== pdir %>/js/materialize.min.js"></script>
%= content 'done_toast'
</body>
</html>
