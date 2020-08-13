#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Long;
use LWP::UserAgent;
use LWP::ConnCache;
use DBI;
use JSON;
use File::Find;
use IO::File;
use Date::Parse;
use POSIX 'strftime';


my $usage = <<EOL;
Usage: $0
$0 requries the environment variable TC_API_KEY to be set in order to run
The value is an API key generated from https://portal.trinitycyber.com
    -b, --begin-time [OPTIONAL]
        The first time to query for in the Trinity Cyber portal, not not used 'begining of time' is assumed
    -e, --end-time [OPTIONAL]
        The last time to query for in the Trinity Cyber portal, not not used 'end of time' is assumed
    -d, --input-dir
        A directory containing (recursively through subdirectories) JSON files produced by perl-scraper.pl
EOL

my $TC_API_KEY = $ENV{'TC_API_KEY'};
die("Environment variable TC_API_KEY not set\n$usage") if not defined $TC_API_KEY;

my $begin_time;
my $end_time;
my $input_dir;
my $client_id;
GetOptions(
  'begin-time|b=s' => \$begin_time,
  'end-time|e=s' => \$end_time,
  'input-dir|d=s' => \$input_dir,
  'client-id|c=i' => \$client_id)
or die $usage;

die "--input-dir/-d is a required parameter\n$usage" unless defined $input_dir;

my $filter = {};
if (defined $begin_time) {
  $filter->{'fromTime'} = $begin_time
}
if (defined $end_time) {
  $filter->{'toTime'} = $end_time
}

my $cache = LWP::ConnCache->new;
$cache->total_capacity(10);

my $ua = LWP::UserAgent->new(conn_cache => $cache);

my $GQL = << 'EOL';
query ExampleQuery($afterCursor: String, $filter: EventFilter) {
  events(first: 250, after: $afterCursor, filter: $filter) {
    totalCount
    pageInfo {
      hasNextPage
      endCursor
    }
    edges {
      node {
        actionTime
        formula {
          formulaId
        }
        applicationData {
          __typename
          ... on HttpRequestData {
            path
            host
            userAgent
          }
        }
      }
    }
  }
}
EOL

my $lastCursorOnPage = undef;

my $dbh = DBI->connect('DBI:SQLite:dbname=:memory:', '', '', { RaiseError => 1 }) or die $DBI::errstr;
if ($dbh->do('CREATE TABLE tc_correlate (action_time TEXT, host TEXT, path TEXT, user_agent TEXT, formula_id INTEGER)') < 0) {
  die $DBI::errstr;
}
$dbh->being_work;

my $haveMorePages = 1;
while ($haveMorePages) {
  my $post_data = {
    "query" => $GQL,
    "variables" => {
      "afterCursor" => $lastCursorOnPage,
      "filter" => $filter
    }
  };
  my $req = HTTP::Request->new('POST', 'https://portal.trinitycyber.com/graphql', [
      'Content-Type' => 'application/json',
      'Authorization' => "Bearer ${TC_API_KEY}"
    ],
    encode_json($post_data)
  );
  if (defined $client_id) {
    $req->header('X-Effective-Client-Ids', "$client_id");
  }
  my $resp = $ua->request($req);
  if (!$resp->is_success) {
    print "Failed to make request:\n" . $resp->as_string() . "\n";
    $haveMorePages = 0;
  }
  else {
    my $content = decode_json($resp->decoded_content);
    $haveMorePages = $content->{'data'}->{'events'}->{'pageInfo'}->{'hasNextPage'};
    $lastCursorOnPage = $content->{'data'}->{'events'}->{'pageInfo'}->{'endCursor'};
    foreach my $nodeContainer (@{$content->{'data'}->{'events'}->{'edges'}}) {
      my $node = $nodeContainer->{'node'};
      foreach my $appData (@{$node->{'applicationData'}}) {
        if ($appData->{'__typename'} eq 'HttpRequestData') {
          my $sth = $dbh->prepare('INSERT INTO tc_correlate (action_time, host, path, user_agent, formula_id) VALUES (?, ?, ?, ?, ?)');
          $sth->bind_param(1, $node->{'actionTime'});
          $sth->bind_param(2, $appData->{'host'});
          $sth->bind_param(3, $appData->{'path'});
          $sth->bind_param(4, $appData->{'userAgent'});
      	  $sth->bind_param(5, $node->{'formula'}->{'formulaId'});
          $sth->execute();
        }
      }
    }
  }
}
$dbh->commit();

my $results;

sub find_json_check {
  if ($File::Find::name =~ m#/[0-9]+\.json$#) {
    my $fh = IO::File->new($File::Find::name, "r+");
    my $json_text;
    {
      local $\ = undef;
      $json_text = <$fh>;
    }
    my $json = json_parse($json_text);
    my $url = $json->{'url'};
    my $user_agent = $json->{'request_headers'}->{'User-Agent'};
    my $host;
    my $path;
    if ($url =~ m#^http(s?)://([^/]*).*$#) {
      $host = $1;
      $path = $2;
    }
    $path = '/' unless defined $path;
    # Account for partial seconds in actino time / clock skew
    my @start_time = Date::Parse::strptime($json->{'start_timestamp'});
    $start_time[0] -= 2;
    my @stop_time = Date::Parse::strptime($json->{'stop_timestamp'});
    $stop_time[0] += 2;
    my $sth = $dbh->prepare('SELECT formula_id, host, path, user_agent, action_time FROM tc_correlate WHERE host like ? AND path like ? AND user_agent like ? AND action_time BETWEEN ? AND ?');
    $sth->bind_param(1, $host);
    $sth->bind_param(2, $path);
    $sth->bind_param(3, $user_agent);
    $sth->bind_param(4, strftime("%F %T", @start_time));
    $sth->bind_param(5, strftime("%F %T", @stop_time));
    $sth->execute();
    my $formula_id;
    my $action_time;
    while (($formula_id, $host, $path, $user_agent, $action_time) = $sth->fetchrow()) {
      push(@{$json->{'trinity_cyber_matches'}}, {
        'formula_id' => $formula_id,
        'action_time' => $action_time,
        'host' => $host,
        'path' => $path,
        'user_agent' => $user_agent,
      })
    }
    $sth->finish();
  } 
}

find({'wanted' => \&find_json_check, 'no_chdir' => 1}, $input_dir);

$dbh->disconnect();
