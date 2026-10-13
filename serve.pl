#!/usr/bin/env perl
# Tiny dependency-free static file server for local preview.
# Usage: perl serve.pl [port]   (default 8000)
use strict;
use warnings;
use IO::Socket::INET;

my $port = shift // 8000;
my %types = (
  html => 'text/html; charset=utf-8',
  css  => 'text/css; charset=utf-8',
  js   => 'text/javascript; charset=utf-8',
  json => 'application/json',
  webmanifest => 'application/manifest+json',
  svg  => 'image/svg+xml',
  png  => 'image/png',
  jpg  => 'image/jpeg',
  jpeg => 'image/jpeg',
  gif  => 'image/gif',
  ico  => 'image/x-icon',
);

my $server = IO::Socket::INET->new(
  LocalPort => $port, Proto => 'tcp', Listen => 16, Reuse => 1,
) or die "Cannot listen on $port: $!\n";

print "Serving on http://localhost:$port/  (Ctrl-C to stop)\n";

while (my $client = $server->accept) {
  $client->autoflush(1);
  my $req = <$client>;
  next unless defined $req;
  while (my $line = <$client>) { last if $line =~ /^\r?\n$/; }

  my ($method, $path) = $req =~ /^(\S+)\s+(\S+)/;
  $path = '/index.html' if !defined $path || $path eq '/';
  $path =~ s/\?.*$//;
  $path =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/ge;
  $path =~ s/^\/+//;
  $path = 'index.html' if $path eq '';
  $path =~ s{\.\./}{}g;

  if ($method && $method ne 'GET' && $method ne 'HEAD') {
    print $client "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n";
    close $client; next;
  }

  unless (-f $path) {
    print $client "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nNot found: $path\n";
    close $client; next;
  }

  open(my $fh, '<', $path) or do {
    print $client "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\n\r\n";
    close $client; next;
  };
  binmode $fh;
  local $/;
  my $body = <$fh>;
  close $fh;

  my ($ext) = $path =~ /\.([^.]+)$/;
  my $ctype = $types{lc($ext // '')} // 'application/octet-stream';

  print $client "HTTP/1.1 200 OK\r\n";
  print $client "Content-Type: $ctype\r\n";
  print $client "Content-Length: " . length($body) . "\r\n";
  print $client "Cache-Control: no-store\r\n";
  print $client "Connection: close\r\n\r\n";
  print $client $body if $method && $method ne 'HEAD';
  close $client;
}
