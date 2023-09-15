#!/usr/bin/perl
# Nessus Result Extractor
# by Tengku Zahasman
#
# supports Nessus 3, 4, 4.2, 4.3 (HTML) and all .nessus file

use strict;
use warnings;
use Getopt::Long;
use File::Basename;
use Cwd 'abs_path';

my $basename = basename($0);

# usage information

sub show_help {

       print <<HELP;

NESSUS HTML PROCESSOR - by z3mms
Version 2 - Accepts .nessus file as input

Usage: ./$basename <path-to-nessus-file> <options>

Example: 
./$basename /blah/nessus.html -t 2
./$basename /blah/nessus.nessus -t 4


Options 't':

		1 -     issues by IP (default)
		2 -     missing patches
		3 -     enumerate open ports	   
		4 -     missing patches (formatted for XLS)
		5 -		enumerate password policies
		6 - 	get outdated software list
		7 -		CIS benchmark (formatted for XLS)

Options:

       -h      Help
       -f      Path to nessus file (nessus.html by default)

HELP
       exit 1;
}

# declare variables

my $file = $ARGV[0];
my $help = 0;
my $type = 0;
my @line;

GetOptions(

       "t=n" => \$type,
       "f=s" => \$file,
       'h'       => \$help,

) or show_help;
$help and show_help;
!defined($file) and show_help;

# start
nessusify($type);

# nessusify!
sub nessusify {
       ($type) = @_;
       open (FILE, $file)
               or die "Cannot open ".$file.": ".$!;
		if ($type == 1) { issues(); }
		elsif ($type == 2) { missingOsPatches(); }
		elsif ($type == 3) { openPorts(); }
	   	elsif ($type == 4) { missingOsPatchesFormatted(); }
		elsif ($type == 5) { passwordPolicy(); }
		elsif ($type == 6) { getOutdatedSoftware(); }
		elsif ($type == 7) { cisBenchmark(); }
       else { issues(); }
       close (FILE);
}

# get the missing OS patches
sub missingOsPatches {

    # generic variable
	my $i = 0;
	my $osflag = 0;
	my $nbtflag = 0;	
	my $dnsflag = 0;
	my $count = 0;
	my @patches;

       while(<FILE>) {

		   # grep IP first
		   if (/size=\+2>(\d+\.\d+\.\d+\.\d+)/ # nessus 3
		   || /<td align="right"><a name="(\d+\.\d+\.\d+\.\d+)">(\d+\.\d+\.\d+\.\d+)<\/a><\/td>/ # nessus 4
		   || /<TD align="left" class="ip_sev_\w+">(\d+\.\d+\.\d+\.\d+)<\/TD><\/TR>/ # nessus 4.2
		   || /<td class="ip_sev_\w+" align="left">(\d+\.\d+\.\d+\.\d+)<\/td><\/tr>/ # nessus 4.3
		   || /<h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/ # nessus 5
		   || /<h2 id="id\w\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/
		   || /<span xmlns="" class="classsection"><h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2><\/span>/
		   || /<ReportHost name="(\d+\.\d+\.\d+\.\d+)"><HostProperties>/ # .nessus file
		) {
			if ($count != 0 || eof) {
									@patches = sort(@patches);
									my $i = 0;
									print join (', ', @patches);
									print ", Number of missing patches: " . $count . "\n";
									$count = 0;
									@patches = ();
				}

			print "\n-------------------------\nIP: ". $1 . "\n";
	
			}

        # flag OS
		if (/(.*)OS:<\/font><\/span><\/p><\/td>/) {
			$osflag = 1;
		}
			
		# flag NETBIOS name
		if (/(.*)Netbios Name:<\/font><\/span><\/p><\/td>/) {
			$nbtflag = 1;		
		}

		# flag DNS name
		if (/(.*)DNS Name:<\/font><\/span><\/p><\/td>/) {
            $dnsflag = 1;
        }

		# grep OS
		if (/color="\#053958">(.*)<\/font><\/span><\/p><\/td>/ && $1 ne "OS:"  && $osflag == 1
		|| /<tag name="operating-system">(.*)<\/tag>/) {
			print "OS: ".$1 . "\n";
			$osflag = 0;
        }

		# grep NETBIOS name
		if (/color="\#053958">(.*)<\/font><\/span><\/p><\/td>/ && $1 ne "Netbios Name:"  && $nbtflag == 1
		|| /<tag name="netbios-name">(.*)<\/tag>/) {
			print "Netbios: ".$1 . "\n";
			$nbtflag = 0;
		}
		
		# grep DNS name
		if (/color="\#053958">(.*)<\/font><\/span><\/p><\/td>/ && $1 ne "DNS Name:"  && $dnsflag == 1
		|| /<tag name="host-fqdn">(.*)<\/tag>/) {
            print "DNS: ".$1 . "\n";
            $dnsflag = 0;
         }


               # grep missing patches
               if (/<td width="85%" align="left">\d+ - (MS\d+\-\d+): (.*)<\/td>/ || /<td align="left" width="85%">\d+ - (MS\d+\-\d+): (.*)<\/td>/ || 
					/<td width="85%" align="left">\d+ - (RHSA\-\d+\-\d+): (.*)<\/td>/ || /<td align="left" width="85%">\d+ - (RHSA\-\d+\-\d+): (.*)<\/td>/ ||
					/<td width="85%" align="left">\d+ - Solaris \d+ \(sparc\) : (\d+\-\d+)<\/td>/ || /<td align="left" width="85%">\d+ - Solaris \d+ \(sparc\) : (\d+\-\d+)<\/td>/ || 
					/<td width="85%" align="left">\d+ - AIX \d+ : (.*)<\/td>/ || /<td align="left" width="85%">\d+ - AIX \d+ : (.*)<\/td>/ || 
					/<td width="85%" align="left">\d+ - (VMSA\-\d+\-\d+) : (.*)<\/td>/ || /<td align="left" width="85%">59506 - (VMSA\-\d+\-\d+) : (.*)<\/td>/
					|| /\- (MS\d+\-\d+) \( http\:\/\/technet\.microsoft\.com\/en\-us\/security\/bulletin\/ms\d+\-\d+ \)/
				)  {

					#print $1 . ", ";
					push(@patches, $1);
					$count++
               }
			   
			   if (eof) {
									@patches = sort(@patches);
									my $i = 0;
									print join (', ', @patches);
									print ", Number of missing patches: " . $count . "\n";
									$count = 0;
									@patches = ();
				}
       }
}



# enumerate open ports

sub openPorts {

       my $portstring;
	   my $currentport;
	   my $foundport;
       my @ports;



       while(<FILE>) {

               # grep IP first
               if (/size=\+2>(\d+\.\d+\.\d+\.\d+)/ # nessus 3
               || /<td align="right"><a name="(\d+\.\d+\.\d+\.\d+)">(\d+\.\d+\.\d+\.\d+)<\/a><\/td>/ # nessus 4
               || /<TD align="left" class="ip_sev_\w+">(\d+\.\d+\.\d+\.\d+)<\/TD><\/TR>/ # nessus 4.2
               || /<td class="ip_sev_\w+" align="left">(\d+\.\d+\.\d+\.\d+)<\/td><\/tr>/ # nessus 4.3
			   || /<h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/ # nessus 5
			   || /<h2 id="id\w\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/	
			   || /<span xmlns="" class="classsection"><h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2><\/span>/
			   || /<ReportHost name="(\d+\.\d+\.\d+\.\d+)"><HostProperties>/ # .nessus file
               ) {
                       print "-------------------------\nIP: ". $1 . "\n";
               }


               # grep open port
               if (/<font color=#FFFFFF>Port (.*)<\/font>/ # nessus 3
               || /<div>(.*)<\/div>/ # nessus 4
               || /<TD align="left" class="port_header_label">Port (.*)<\/TD><TD align="right"/ # nessus 4.2
               || /<td class="port_header_label" align="left">Port (.*)<\/td><td class="toggle"/ # nessus 4.3
			   || /<h2>Ports<\/h2><\/span><span class="classh2"><font color="#\w+"><h2>(.*)<\/h2>/ # nessus 5
			   || /<ReportItem port="(\d+)" svc_name="(.*)" protocol="(udp|tcp)"/
               ) {
                       $currentport = $1;
						if ($currentport != 0 && $currentport != $foundport) {
						print $2 . " (" . $currentport . "/".$3.")\n";
						$foundport = $currentport;
						}
               }
       }
}

# get risk issues

sub issues {

       my $ip = 0;
       my $title = "";

       while(<FILE>) {

               # grep IP first
               if (/size=\+2>(\d+\.\d+\.\d+\.\d+)/ # nessus 3
               || /<td align="right"><a name="(\d+\.\d+\.\d+\.\d+)">(\d+\.\d+\.\d+\.\d+)<\/a><\/td>/ # nessus 4
               || /<TD align="left" class="ip_sev_\w+">(\d+\.\d+\.\d+\.\d+)<\/TD><\/TR>/ # nessus 4.2
               || /<td class="ip_sev_\w+" align="left">(\d+\.\d+\.\d+\.\d+)<\/td><\/tr>/ # nessus 4.3
				|| /<h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/ # nessus 5
				|| /<h2 id="id\w\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/				
				|| /<span xmlns="" class="classsection"><h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2><\/span>/				
				|| /<tag name="host-ip">(\d+\.\d+\.\d+\.\d+)<\/tag>/ # .nessus file
               ) {
                       $ip = $1;
               }

               # grep titles
               if (/<td align=left colspan=2><b><font color="#FFFFFF">(.*)<\/font><\/b><\/align><\/td>/ # nessus 3
               || /Synopsis<\/b> :<br\/><br\/>(.*)\.\s?<br\/><br\/><br\/>/ # nessus 4
               || /<TD align="left" class="plugin_label">(.*)<\/TD><\/TR>/ # nessus 4.2
               || /<td class="plugin_label" align="left">(.*)<\/td><\/tr>/ # nessus 4.3
				|| /<td width="85%" align="left">\d+ - (.*)<\/td>/ || /<td align="left" width="85%">\d+ - (.*)<\/td>/ # nessus 5				
				|| /pluginName="(.*)" pluginFamily=/ # .nessus file
               ) {
                       $title = $1;
               }

               # grep severity and print
               if (/<b>Risk factor :<\/b><br><br>(\w+) \/ CVSS Base Score/ # nessus 3
               || /<b>Risk Factor<\/b> :<br\/><br\/>(\w+) \/ CVSS Base Score/ # nessus 4
               || /<b>Risk Factor<\/b> :<br\/><br\/>(\w+)/ # nessus 4 (variant 2)
               || /<B>Risk factor:<\/B><BR\/>(\w+)<BR\/>/ # nessus 4.2
               || /<b>Risk factor:<\/b><br>(\w+)<br>/ # nessus 4.3
				|| /<h2>Risk Factor<\/h2><\/span><p><span class="classtext"><font style="font-weight: normal;" color="#053958">(.*)<\/font><\/span><\/p>/ # nessus 5
				|| /<h2>Risk Factor<\/h2><\/span><p><span class="classtext"><font color="#053958" style="font-weight: normal">(.*)<\/font><\/span><\/p>/
				|| /<h2>Risk Factor<\/h2><\/span><p><span class="classtext"><font style="font-weight: normal" color="#053958">(.*)<\/font><\/span><\/p>/
				|| /<risk_factor>(.*)<\/risk_factor>/ # .nessus file
               ) {
                       print $ip . "\t" . $title . "\t" . uc($1) . "\n";
               }
       }
}

# get the missing OS patches Formatted

sub missingOsPatchesFormatted {

       # generic variable
		my $i = 0;
		my $osflag = 0;
		my $nbtflag = 0;
		my $dnsflag = 0;
		my $count = 0;
		my @patches;

       while(<FILE>) {

               # grep IP first
               if (/size=\+2>(\d+\.\d+\.\d+\.\d+)/ # nessus 3
               || /<td align="right"><a name="(\d+\.\d+\.\d+\.\d+)">(\d+\.\d+\.\d+\.\d+)<\/a><\/td>/ # nessus 4
               || /<TD align="left" class="ip_sev_\w+">(\d+\.\d+\.\d+\.\d+)<\/TD><\/TR>/ # nessus 4.2
               || /<td class="ip_sev_\w+" align="left">(\d+\.\d+\.\d+\.\d+)<\/td><\/tr>/ # nessus 4.3
				|| /<h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/ # nessus 5
				|| /<h2 id="id\w\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/
				|| /<span xmlns="" class="classsection"><h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2><\/span>/
				|| /<ReportHost name="(\d+\.\d+\.\d+\.\d+)"><HostProperties>/ # .nessus file
               ) {
			
				if ($count != 0 || eof) {
								@patches = sort(@patches);
								my $i = 0;
								print join (', ', @patches);
                                print ", Number of missing patches: " . $count;
                                $count = 0;
								@patches = ();
                        }
                       print "\n" . $1 . "\t";
               }

				# flag OS
                if (/(.*)OS:<\/font><\/span><\/p><\/td>/) {
                        $osflag = 1;
                }

                # flag NETBIOS name
                if (/(.*)Netbios Name:<\/font><\/span><\/p><\/td>/) {
                        $nbtflag = 1;
                }

                # flag DNS name
                if (/(.*)DNS Name:<\/font><\/span><\/p><\/td>/) {
                        $dnsflag = 1;
                }

                # grep OS
                if (/color="\#053958">(.*)<\/font><\/span><\/p><\/td>/ && $1 ne "OS:"  && $osflag == 1
				|| /<tag name="operating-system">(.*)<\/tag>/) {
                       print $1 . "\t";
                        $osflag = 0;
               }

                # grep NETBIOS name
                if (/color="\#053958">(.*)<\/font><\/span><\/p><\/td>/ && $1 ne "Netbios Name:"  && $nbtflag == 1
				|| /<tag name="netbios-name">(.*)<\/tag>/) {
                        print $1 . "\t";
                        $nbtflag = 0;
                }

		# grep DNS name
                if (/color="\#053958">(.*)<\/font><\/span><\/p><\/td>/ && $1 ne "DNS Name:"  && $dnsflag == 1
				|| /<tag name="host-fqdn">(.*)<\/tag>/) {
                        print $1 . "\t";
                        $dnsflag = 0;
                }


               # grep missing patches
		if (/<td align="left" width="85%">\d+ - (MS\d+\-\d+): (.*)<\/td>/ ||	/<td width="85%" align="left">\d+ - (MS\d+\-\d+): (.*)<\/td>/ ||
				/<td width="85%" align="left">\d+ - (RHSA\-\d+\-\d+): (.*)<\/td>/ || /<td align="left" width="85%">\d+ - (RHSA\-\d+\-\d+): (.*)<\/td>/ ||
                /<td width="85%" align="left">\d+ - Solaris \d+ \(sparc\) : (\d+\-\d+)<\/td>/ || /<td align="left" width="85%">\d+ - Solaris \d+ \(sparc\) : (\d+\-\d+)<\/td>/ || 
				/<td width="85%" align="left">\d+ - AIX \d+ : (.*)<\/td>/ || /<td align="left" width="85%">\d+ - AIX \d+ : (.*)<\/td>/ || 
				/<td width="85%" align="left">\d+ - (VMSA\-\d+\-\d+) : (.*)<\/td>/ || /<td align="left" width="85%">59506 - (VMSA\-\d+\-\d+) : (.*)<\/td>/ ||
				/\- (MS\d+\-\d+) \( http\:\/\/technet\.microsoft\.com\/en\-us\/security\/bulletin\/ms\d+\-\d+ \)/
				)	{

                # print $1 . ", ";
				push(@patches, $1);
                $count++
               }
			   
			   if (eof) {
									@patches = sort(@patches);
									my $i = 0;
									print join (', ', @patches);
									print ", Number of missing patches: " . $count . "\n";
									$count = 0;
									@patches = ();
			}
       }
}

sub passwordPolicy {
		
	
		while(<FILE>) {	
			# grep IP first
             if (/size=\+2>(\d+\.\d+\.\d+\.\d+)/ # nessus 3
	       	       || /<td align="right"><a name="(\d+\.\d+\.\d+\.\d+)">(\d+\.\d+\.\d+\.\d+)<\/a><\/td>/ # nessus 4
	       	       || /<TD align="left" class="ip_sev_\w+">(\d+\.\d+\.\d+\.\d+)<\/TD><\/TR>/ # nessus 4.2
	       	       || /<td class="ip_sev_\w+" align="left">(\d+\.\d+\.\d+\.\d+)<\/td><\/tr>/ # nessus 4.3
			|| /<h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/ # nessus 5
			|| /<h2 id="id\w\d+">(\d+\.\d+\.\d+\.\d+)<\/h2>/	
		    || /<span xmlns="" class="classsection"><h2 id="id\d+">(\d+\.\d+\.\d+\.\d+)<\/h2><\/span>/
		    || /<ReportHost name="(\d+\.\d+\.\d+\.\d+)"><HostProperties>/ # .nessus file
	        	       ) {
				print "----------------------\n";
        	               print $1 . "\n";
	   	       }

			# minimum password length
			if (/Minimum password len: (.*)/) {
				print "Minimum password len: " . $1 . "\n";
			}

			# password history length
			if (/Password history len: (.*)/) {
				print "Password history len: " . $1 . "\n";
			}
			
			# max password age
			if (/Maximum password age \(d\): (.*)/) {
				print "Maximum password age (d): " . $1 . "\n";
			}

			# complexity requirement enabled? 
			if (/Password must meet complexity requirements: (.*)/) {
				print "Password must meet complexity requirements: " . $1 . "\n";
			}

			# min password age
			if (/Minimum password age \(d\): (.*)/) {
				print "Minimum password age (d): " . $1 . "\n";
			}

			# forced logoff time
			if (/Forced logoff time \(s\): (.*)/) {
				print "Forced logoff time (s): " . $1 . "\n";
			}

			# locked out time
			if (/Locked account time \(s\): (.*)/) {
				print "Locked account time (s): " . $1 . "\n";
			}

			# time between failed logon
			if (/Time between failed logon \(s\): (.*)/) {
				print "Time between failed logon (s): " . $1 . "\n";
			}

			# number of invalid logon before lockout
			if (/Number of invalid logon before locked out \(s\): (.*)/) {
				print "Number of invalid logon before locked out: " . $1 . "\n";
			}
		}
}


sub getOutdatedSoftware {

	system('cat ' . $file . '>master.nessus');

	listOutdatedSoftware ("Flash Player");
	listOutdatedSoftware ("Shockwave Player");
	listOutdatedSoftware ("Adobe Reader");
	listOutdatedSoftware ("Adobe AIR");
	listOutdatedSoftware ("Java");
	listOutdatedSoftware ("Wireshark");
	listOutdatedSoftware ("Firefox");
	listOutdatedSoftware ("VLC Player");
	listOutdatedSoftware ("Google Chrome");
	
	system('rm master.nessus');
}

sub listOutdatedSoftware {

	my $software = shift;
	
	print "Outdated " . $software . " version\n";
	print "-------------------------------\n";
	system(abs_path($0) .' -f master.nessus | grep "Multiple Vulnerabilities" | grep "' . $software . '" | cut -f1 | uniq');
	print "\n";
	
}

sub cisBenchmark {
	
	while (<FILE>) {
		
		if  (/<cm:compliance-check-name>(.*)<\/cm:compliance-check-name>/) {
			my $string = $1 . "\t";
			$string =~ s/&apos;/'/ig;
			print $string;
		}
		
		if (/<cm:compliance-result>(.*)<\/cm:compliance-result>/) {
			print $1 . "\n";
		}
	}
}


