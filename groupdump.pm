package SRP::Command::groupdump;
use Mojo::Base 'Mojolicious::Command';
use Net::LDAP qw(LDAP_SUCCESS LDAP_INSUFFICIENT_ACCESS);
use Net::LDAP::Util qw(canonical_dn);

has description => 'Dump security groups';
has usage => "Usage: APPLICATION groupdump\n";

sub run {
  my $self = shift;
  my $app = $self->app;

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

  foreach my $sg (@{$app->config('sec_groups')}) {
    say "Group: ".$sg->{dn};

    # search ldap for group members
    my $res = $ldap->search(base => $sg->{dn}, filter => '(objectClass=group)', scope => 'base', attrs => ['member']);
    if ($res->code) {
      $app->log->fatal('Ldap group search error: '.$res->error);
      $ldap->unbind;
      exit 1;
    }
    if ($res->count > 0) {
      my $entry = $res->entry(0);
      foreach my $m ($entry->get_value('member')) {
        say "Member: ".canonical_dn($m);
      }
    } else {
      $app->log->fatal("Ldap group $sg->{dn} is not found in active directory");
      $ldap->unbind;
      exit 1;
    }
    print "\n";
  } #foreach my $sg

  $ldap->unbind;
  $ldap = undef;
  exit 0;
}

1;