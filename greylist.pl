#!/usr/bin/perl
#
#   /var/qmail/bin/greylisting
#   Greylist spam filtering implementation
#
#   Copyright (C) 2007 Vaclav Vobornik
# 
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#   
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#   
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA
#   or see http://ww.gnu.org/licenses/gpl.html.
#
#
require "/opt/greylist/greylist.conf";

#######################################
#         == Main program ==          #
# Don't edit anything below this line #
#######################################

our $CLEAN         = $GREYDIR ."/clean";
our $t_now         = time();
our $t_clean       = $t_now - (stat $CLEAN)[9];

# add a local address into the @IP_WHITELIST
use Sys::Hostname;
use Socket;
push(@IP_WHITELIST,inet_ntoa(scalar gethostbyname(hostname())));

# and index lists
for (@IP_WHITELIST) {$is_ip_wlisted{$_} = 1}
for (@IP_BLACKLIST) {$is_ip_blisted{$_} = 1}
for (@FROM_WHITELIST) {$is_from_wlisted{$_} = 1}
for (@FROM_BLACKLIST) {$is_from_blisted{$_} = 1}

# functions

sub debug {
  my($level,$msg) = @_;
  if ($LOGING >= $level) {
    print STDERR "greylist: LOG$level: $msg\n";
  }
}

sub touch {
  my $file = shift;
  debug(3,"Touching $file");
  open(FILE,">$file");
  close(FILE);
}

sub _exit {
  my $exit = shift;
  debug(1,"Exiting with code $exit");
  exit $exit;
}

sub cleanup {
  if ( $t_clean > $t_cleanup) {
    debug(2,"Time to clean up");
    open(CLEAN,">$CLEAN") or return;
    foreach $file (<$GREYDIR/grey:*>) {
      if (-f $file) {
        debug(3,"Checking $file");
        my $ctime=(stat $file)[8]; # create time
        debug(3,"Create time: $ctime");
        my $mtime=(stat $file)[9]; # modify time
        debug(3,"Modify time: $mtime");
        if ($ctime == $mtime) {
          # only 1 attempt long time ago or
          if ($t_now - $ctime > $t_timeout) {
            debug(2,"Deleting $file - unused time window");
            unlink($file);
          }
        }else{
          # it's long time ago when an email came
          if ($t_now - $mtime > $t_expiry) {
            debug(2,"Deleting $file - inactive sender");
            unlink($file);
          }
        }
      }

    }
    close(CLEAN);
  }
  return;
}


# first, do a clean up
cleanup();

debug(1,"Checking $m_from -> $m_to ($m_ip)");

# isn't it blacklisted?
if ($is_ip_blisted{$m_ip}) {
  debug(2,"$m_ip ($m_from) is blacklisted");
  _exit $e_reject;
}

if ($is_from_blisted{$m_from}) {
  debug(2,"$m_from ($m_ip) is blacklisted");
  _exit $e_reject;
}

# isn't it whitelisted?
if ($is_ip_wlisted{$m_ip}) {
  debug(2,"$m_ip ($m_from) is whitelisted");
  _exit $e_accept;
}

if ($is_from_wlisted{$m_from}) {
  debug(2,"$m_from ($m_ip) is whitelisted");
  _exit $e_accept;
}




# compose a file name

my $filename = "$GREYDIR/grey:$m_to:$m_from:$m_ip";
debug(3,"File name: $filename");

if (-f $filename) {
  debug(2,"File $filename exists, checking the times");
  my $f_ctime=(stat $filename)[8]; # create time
  debug(3,"Create time: $f_ctime");
  my $f_mtime=(stat $filename)[9]; # modify time
  debug(3,"Modify time: $f_mtime");

# non-patient sender:
  if ($t_now - $f_ctime < $t_block) {
    debug(2,"Non-patient sender $filename, recreating the file");
    unlink($filename);
    touch($filename);
    _exit $e_tempreject;
  }else{
    debug(2,"Valid sender $filename, updating the file");
    touch($filename);
    _exit $e_accept;
  }

}else{
  debug(2,"File $filename doesn't exist");
  touch ($filename);
  _exit $e_tempreject;
}



