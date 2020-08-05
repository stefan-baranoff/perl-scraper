#!/usr/bin/perl
use strict;
use warnings;

use Getopt::Long;
use LWP::UserAgent;
use Digest::SHA 'sha256_hex';
use MIME::Base64;
use POSIX 'strftime';
use File::LibMagic;
use File::Path 'make_path';
use JSON;
use IO::Socket::SSL;

# Monkey-patch LWP::Protocol::http to get local address/port information along with remote information
BEGIN {
  use LWP::Protocol::http;
  no warnings 'redefine';
  *LWP::Protocol::http::_get_sock_info = sub
  {
      my($self, $res, $sock) = @_;
      if (defined(my $peerhost = $sock->peerhost)) {
          $res->header("Client-Peer" => "$peerhost:" . $sock->peerport);
      }
      if (defined(my $sockhost = $sock->sockhost)) {
          $res->header("Client-Sock" => "$sockhost:" . $sock->sockport);
      }
  };
  use warnings 'redefine';
}

# Disable line buffering to stdout -- lower throughput but lower latency
$| = 1;

# Read lines from input file into array
sub read_file_lines {
  my $filename = shift;
  my $fh = IO::File->new();
  unless ($fh->open($filename, "r")) {
    die "Could not open [ $filename ] for reading: $!\n";
  }
  my $lines;
  while (<$fh>) {
    $_ =~ s/\r?\n//g;
    push(@{$lines}, $_);
  }
  return $lines;
}

# A list of user-agents to randomly rotate through
my @USER_AGENTS = (
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:79.0) Gecko/20100101 Firefox/79.0",
  "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:79.0) Gecko/20100101 Firefox/79.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 10_15_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/28.0 Mobile/15E148 Safari/605.1.15",
  "Mozilla/5.0 (Android 10; Mobile; rv:68.0) Gecko/68.0 Firefox/68.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
  "Mozilla/5.0 (iPad; CPU OS 13_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/83.0.4147.71 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Mobile Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.105 Safari/537.36",
);
sub get_random_ua_string {
  my $idx = int(rand(scalar(@USER_AGENTS)));
  return $USER_AGENTS[$idx];
}

# Some "referers" to randomly put into the headers
my @REFERERS = (
  "https://www.google.com/",
  "https://www.yahoo.com/",
  "https://www.duckduckgo.com/",
);
# If we only want to randomly add a referer and not always have one, reduce this number
my $REFERER_PERCENTAGE = 1.0;
sub get_referer {
  my $referer_chance = rand();
  if ($referer_chance <= $REFERER_PERCENTAGE) {
    my $idx = int(rand(scalar(@REFERERS)));
    return $REFERERS[$idx];
  }
  return undef;
}

# Given a URL, make an HTTP::Request object to request it with a GET
# Adds a DNT header, an Accept header, Accept-Encoding for gzip if support, and a random referer
# User-agent is handled via the LWP::UserAgent->agent(...) call
sub get_request {
  my $url = shift;

  my $request = HTTP::Request->new('GET', $url, []);
  my $referer = get_referer();
  if ($referer) {
    $request->header('Referer', $referer);
  }
  $request->header('DNT', 1);
  $request->header('Accept', 'text/html,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9');

  # Borrowed from HTTP::Message.pm -- we don't want to advertize everything, just gzip if we can support it
  {
    local $@;
    eval {
      require IO::Uncompress::Gunzip;
      $request->header('Accept-Encoding', 'gzip');
    };
  }

  return $request;
}

# Actually make an HTTP request
# Returns a list of the request object, the response object, and the source port used
# This is NOT using a connection cache so as to be able to provide the source port
# used for the request; there's no clean way to get that otherwise. 
sub make_http_request {
  my $url = shift;

  my $response = undef;
  my $request = undef;
  my $retries = 0;
  # Try up to 3 times if a failure happens
  while ($retries < 3) {
    my $ua = LWP::UserAgent->new(
      ssl_opts => {
        'SSL_verify_mode' => SSL_VERIFY_NONE,
        'verify_hostname' => 0
      }
    );
    # Only give the server limited time if no activity is ongoing
    $ua->timeout(15);
    $ua->agent(get_random_ua_string());
    $request = get_request($url);

    print("Try ${retries} - requesting [ $url ]... ");
    $response = $ua->request($request);
    if (not $response->is_success()) {
      print("FAILED with: " . $response->message() . " - " . length($response->content()) . " bytes content\n");
      $retries++;
    }
    else {
      print("DONE with: " . $response->message() . " - " . length($response->content()) . " bytes content\n");
      # Normal return when things worked
      return ($request, $response);
    }
  }
  return ($request, $response);
}

# Convert an HTTP::Headers object into a structured K/V store
# Multi-value headers are possible so all entries are stored in arrays
# HTTP::Headers does not provide 'raw' data, it only allows 'normalized'
# name values and does not preserve order - it's designed around being
# 'friendly' for the developer and not forensic.
#
# This is good enough to triage with existing capabilities, but is NOT
# diagnostic or forensic in nature! Take the names/values with a grain of salt.
sub get_headers_map {
  my $headers = shift;
  my $header_map = {};
  $headers->scan(sub {
    my $name = shift;
    my $value = shift;
    push(@{$header_map->{$name}}, $value);
  });
  return $header_map;
}

sub ensure_outdir {
  my $outdir = shift;
  if (not -w $outdir) {
    die "Output directory [ $outdir ] is not writable, pick an appropriate output directory and try again.\n";
  }
}

my $usage = <<EOL;
Usage: $0
    -u, --url-list
        A file containing a list of URLs to grab, one per line, starting with the scheme.
        Example file contents:
          https://www.example.com/
          http://www.example.com/second_file.html
          https://www.example.com/this/is/a/full/path
          https://www.example.com:8443/non/stanard/port
    -o, --out-dir
        The directory, which must already exist and be writable, to output results into.
    -a, --user-agents [OPTIONAL]
        A file containing a list of User-Agent values to randomly select from, one per line.
        If not provided a default build-in list is used.
    -r, --referers [OPTIONAL]
        A file containing a list of Referer values to randomly select from, one per line.
        If not provided a default build-in list is used.
EOL

sub main {
  # Parse arguments
  my $url_list_file;
  my $out_dir;
  my $ua_file;
  my $ref_file;
  GetOptions(
    'url-list|u=s' => \$url_list_file,
    'out-dir|o=s' => \$out_dir,
    'user-agents|a:s' => \$ua_file,
    'referers|r:s' => \$ref_file)
  or die $usage;

  if (not defined $url_list_file) {
    die("-u, --url-list is required but not supplied!\n$usage");
  }
  if (not defined $out_dir) {
    die("-o, --out-dir is required but not supplied!\n$usage");
  }

  my $urls = read_file_lines($url_list_file);
  if (defined($ua_file)) {
    @USER_AGENTS = @{read_file_lines($ua_file)};
  }
  if (defined($ref_file)) {
    @REFERERS = @{read_file_lines($ref_file)};
  }
  ensure_outdir($out_dir);

  my @urls = @{read_file_lines($url_list_file)};
  my $url_index = 0;
  my $identifier = File::LibMagic->new();
  foreach my $url (@urls) {
    my $start_time_string = strftime("%FT%T%Z", gmtime());
    my ($request, $response) = make_http_request($url);
    my $stop_time_string = strftime("%FT%T%Z", gmtime());

    my $request_headers_map = get_headers_map($request->headers());
    my $response_headers_map = get_headers_map($response->headers());
    # charset => none SHOULD return a byte stream (result of Encode)
    # and only 'decode' transfer encoding (gzip, chunk, etc.) and not charset
    my $content = $response->decoded_content('charset' => 'none');
    my ($dest_addr, $dest_port, $src_addr, $src_port);
    if (defined($response->header('Client-Peer'))) {
       ($dest_addr, $dest_port) = split(/:([0-9]+)$/, $response->header('Client-Peer'));
       # Number-ify dest_port
       $dest_port = $dest_port + 0;
    }
    if (defined($response->header('Client-Sock'))) {
       ($src_addr, $src_port) = split(/:([0-9]+)$/, $response->header('Client-Sock'));
       # Number-ify src_port
       $src_port = $src_port + 0;
    }

    # Create metadata about this download
    my $result = {
      'start_timestamp' => $start_time_string,
      'stop_timestamp' => $stop_time_string,
      'url' => $url,
      'source_address' => $src_addr,
      'source_port' => $src_port,
      'destination_address' => $dest_addr,
      'destination_port' => $dest_port,
      'request_headers' => $request_headers_map,
      'response_status' => $response->code(),
      'response_status_message' => $response->message(),
      'response_headers' => $response_headers_map,
    };
    if ($response->code() >= 400 && defined($response->header('Client-Warning'))) {
      $result->{'content_sha256'} = "INTERNAL_ERROR";
    }
    elsif (not defined($content)) {
      $result->{'content_sha256'} = "NO_CONTENT";
    }
    else {
      $result->{'content_sha256'} = sha256_hex($content);
      $result->{'libmagic_info'} = $identifier->info_from_string($content)
    }

    ## TODO: This should probably be functionized if used more than just these 2 times
    # Save metadata to file in subdirectory for SHA256 sum named for the index of the URL it came from
    my $fh = IO::File->new();
    my $mime_fixed;
    if (defined($result->{'libmagic_info'})) {
      $mime_fixed = $result->{'libmagic_info'}->{'mime_type'};
      $mime_fixed =~ s#/#__#g;
    }
    else {
      $mime_fixed = "NO_MIMETYPE";
    }
    my $subdir_name = "$out_dir/$mime_fixed/$result->{'content_sha256'}";
    if (! -d $subdir_name) {
      make_path($subdir_name);
    }
    my $metafile_name = "$subdir_name/$url_index.json";
    unless ($fh->open("$metafile_name", "w")) {
      die "Could not open [ $metafile_name ] for writing: $!\n";
    }
    # Only using UTF-8 because we're JSON-ifying, if this were binary data we'd need :raw
    $fh->binmode(':encoding(UTF-8)');
    $fh->write(to_json($result, {utf8 => 1, pretty => 1, convert_blessed => 1, canonical => 1})) or die "Failed to write to [ $metafile_name ]: $!\n";

    if (defined($content)) {
      ## TODO: This should probably be functionized if used more than just these 2 times
      # Save data to file in subdirectory for SHA256 sum named for the index of the URL it came from
      my $datafile_name = "$subdir_name/$url_index.dat";
      $fh = IO::File->new();
      unless ($fh->open("$datafile_name", "w")) {
        die "Could not open [ $datafile_name ] for writing: $!\n";
        $fh->binmode(':raw');
      }
      $fh->write($content) or die "Failed to write to [ $datafile_name ]: $!\n";
    }

    $url_index++;
  }
}


main();
