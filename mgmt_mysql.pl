use Mojolicious::Lite;

#
# Copyright (C) 2015 by Mateusz Hromada
# Approved by Zawoor (znalazł błąd => dostał wafelka)
#

use strict;
use utf8;
use Carp;

use DBI;

my $DB;
my $DRH;

my $config = plugin 'JSONConfig' => { file => 'mgmt_mysql.conf' };
app->secret( $config->{app}->{secret} );
$DB = DBI->connect(
    $config->{db}->{dsn},
    $config->{db}->{user},
    $config->{db}->{password},
    { RaiseError => 1, PrintError => 0, mysql_auto_reconnect => 1 }
) or die $DBI::errstr;

$DRH = DBI->install_driver('mysql');

get '/mysql/users' => sub {
    my $c = shift;
    $c->res->headers->cache_control('max-age=1, no-cache');

    my $sth = $DB->prepare_cached("SELECT user FROM mysql.user");
    eval { $sth->execute(); };
    if ($@) {
        $c->rendered(503);
        return;
    }
    my @users = map @$_, @{ $sth->fetchall_arrayref };
    $c->render( json => [@users] );
};

post '/mysql/users' => sub {
    my $c = shift;
    $c->res->headers->cache_control('max-age=1, no-cache');

    my $content_type = $c->req->headers->content_type;
    if ( $content_type !~ q|^application/json(?:;\S+)?$| ) {
        $c->rendered(415);
        return;
    }

    my $req = $c->req->json;
    unless ( defined $req ) {
        $c->rendered(400);
        return;
    }

    my $name = $req->{name};

    my $sth = $DB->prepare_cached("CREATE USER ?");
    eval { $sth->execute($name); };
    if ($@) {
        $c->render( json => { error => $@ }, status => 409 );
        return;
    }
    $c->rendered(204);
};

put '/mysql/users/#name' => sub {
    my $c = shift;
    $c->res->headers->cache_control('max-age=1, no-cache');

    my $content_type = $c->req->headers->content_type;
    if ( $content_type !~ q|^application/json(?:;\S+)?$| ) {
        $c->rendered(415);
        return;
    }

    my $req = $c->req->json;
    unless ( defined $req ) {
        $c->rendered(400);
        return;
    }

    my $name     = $c->param('name');
    my $password = $req->{password};

    if ( $name eq 'root' ) {
        $c->render( json => { error => 'Bad user: root' }, status => 403 );
        return;
    }

    my $sth = $DB->prepare_cached("SET PASSWORD FOR ? = PASSWORD(?)");
    eval { $sth->execute( $name, $password ); };
    if ($@) {
        $c->render( json => { error => $@ }, status => 404 );
        return;
    }
    $c->rendered(204);

};

get '/mysql/databases' => sub {
    my $c = shift;
    $c->res->headers->cache_control('max-age=1, no-cache');

    my $sth = $DB->prepare_cached("SHOW DATABASES");
    eval { $sth->execute(); };
    if ($@) {
        $c->rendered(503);
        return;
    }
    my @dbs = map @$_, @{ $sth->fetchall_arrayref };
    $c->render( json => [@dbs] );
};

post '/mysql/databases' => sub {
    my $c = shift;
    $c->res->headers->cache_control('max-age=1, no-cache');

    my $content_type = $c->req->headers->content_type;
    if ( $content_type !~ q|^application/json(?:;\S+)?$| ) {
        $c->rendered(415);
        return;
    }

    my $req = $c->req->json;
    unless ( defined $req ) {
        $c->rendered(400);
        return;
    }

    my $owner = $req->{owner};
    my $name  = $req->{name};

    unless (
        $DRH->func(
            'createdb',                $DB->quote_identifier($name),
            $config->{db}->{host},     $config->{db}->{user},
            $config->{db}->{password}, 'admin'
        )
      )
    {
        $c->rendered(409);
        return;
    }

    my $sth =
      $DB->prepare_cached( "GRANT ALL PRIVILEGES ON "
          . $DB->quote_identifier($name)
          . ".* TO ?\@'%'" );

    $sth->execute($owner);

    $c->rendered(204);
};

del '/mysql/databases/#name' => sub {
    my $c = shift;

    my $name = $c->param('name');

    if ( $name eq 'mysql' ) {
        $c->render( json => { error => 'Bad database: mysql' }, status => 403 );
        return;
    }

    $DRH->func(
        'dropdb',
        $DB->quote_identifier($name),
        $config->{db}->{host},
        $config->{db}->{user},
        $config->{db}->{password}, 'admin'
    );

    $c->rendered(204);
};

any '/*any' => { any => '' } => sub {
    my $c = shift;
    $c->rendered(404);
};

app->start;
