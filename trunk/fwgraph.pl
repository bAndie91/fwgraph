#!/usr/bin/env perl

use Data::Dumper;
use XML::Simple;
use Getopt::Long;
undef $/;
$\ = "\n";


@bChainFlow = (
	["network-1",			["raw", "PREROUTING"]],
	[["raw", "PREROUTING"], 	["mangle", "PREROUTING"]],
	[["mangle", "PREROUTING"], 	["nat", "PREROUTING"]],
	[["nat", "PREROUTING"], 	"routing_decision-1"],
	["routing_decision-1", 		["mangle", "INPUT"]],
	["routing_decision-1", 		["mangle", "FORWARD"]],
	[["mangle", "INPUT"], 		["nat", "INPUT"]],
	[["nat", "INPUT"], 		["filter", "INPUT"]],
	[["filter", "INPUT"],		"local_process-1"],
	[["mangle", "FORWARD"], 	["filter", "FORWARD"]],
	[["filter", "FORWARD"], 	["mangle", "POSTROUTING"]],
	[["mangle", "POSTROUTING"], 	["nat", "POSTROUTING"]],
	[["nat", "POSTROUTING"],	"network-2"],
	["local_process-2",		["raw", "OUTPUT"]],
	[["raw", "OUTPUT"], 		["mangle", "OUTPUT"]],
	[["mangle", "OUTPUT"], 		["nat", "OUTPUT"]],
	[["nat", "OUTPUT"], 		["filter", "OUTPUT"]],
	[["filter", "OUTPUT"], 		"routing_decision-2"],
	["routing_decision-2",	 	["mangle", "POSTROUTING"]],
	["routing_decision-2",	 	["filter", "INPUT"]],
);

@sameRankHelper = (
      [["raw", "PREROUTING"], 		["raw", "OUTPUT"]],
      [["mangle", "PREROUTING"],	["mangle", "OUTPUT"]],
      [["nat", "PREROUTING"], 		["nat", "OUTPUT"]],
);


%targetColor = qw/DROP pink ACCEPT 90EE90 REJECT FDE68E REDIRECT lightblue NFQUEUE lightblue/;
%callName = qw/j jump g goto P policy/;
%callColor = qw/j black g black P darkgreen/;
%callStyle = qw/j solid g bold P bold/;
# terminatingTarget: 0 - non-terminating, 1 - terminating, 2 - undefined
%terminatingTarget = qw/DROP 1 ACCEPT 1 REJECT 1 REDIRECT 1 NFQUEUE 1 RETURN 2/;
%noDisplayCondition = qw/comment 1/;

%optionRewrite = qw/d dst s src i in o out/;
%arrows = qw/l ← r → t ↑ b ↓ s ➤/;

$rankDirection = "LR";
$Splines = "true";
$quiet_output = 0;

GetOptions(
    'd|direction=s'	=> \$rankDirection,
    'l|splines=s'	=> \$Splines,
    'q|quiet'		=> \$quiet_output,
) or
die "Usage: $0 [--direction {LR|TB|RL|BT} | --splines {none|false|polyline|curved|ortho|true}]\n";

$rankDirection = uc $rankDirection;
if($rankDirection !~ /^(LR|TB|RL|BT)$/) {
	die "Direction (-d) must one of: LR TB RL BT.\n";
}



if(-f $ARGV[0]) {
	open $save, $ARGV[0];
	$ipt = <$save>;
	close $save;
}
elsif(!-t 0) {
	$ipt = <STDIN>;
}
else {
	open $save, '-|', "iptables-save";
	$ipt = <$save>;
	close $save;
}

die "Usage: sudo iptables-save | $0\n   or: $0 iptables.txt\n" if not defined $ipt;


sub parseRuleStr {
	my $_ = shift;
	my %r;
	my $j = "condition";
	#$r{"raw"} = $_;
	while(/^(!?)\s*--?(\S+)\s*("[^""]+"|(?:[^!-]\S*\s*)+)?\s*/)
	{
		my $exclam = $1;
		my $neg = $1 ? "negative" : "positive";
		my $opt = $2;
		my $val = $3;
		$_ = $';
		$val =~ s/\s*$//;
		if($val eq '') {
			undef $val;
		}
		else {
			$val =~ s/^"([^""]+)"$/$1/;
		}
		$j = "action" if $opt =~ /^[jg]$/;
		if(defined $optionRewrite{$opt}) {
			$opt = $optionRewrite{$opt};
		}
		if($opt eq 'm') {
			push @{$r{$opt}}, $val;
		}
		else {
			if($j eq "condition") {
				$r{$j}->{$neg}->{$opt} = $r{$j}->{"all"}->{$exclam.$opt} = $val;
			}
			else {
				if($opt eq 'j' or $opt eq 'g') {
					$r{"call_type"} = $opt;
					if($opt eq 'j') {
						$r{"calling"} = "jump";
					}
					elsif($opt eq 'g') {
						$r{"calling"} = "goto";
					}
					$r{"calling"} .= " $val";
					$r{"target"} = $val;
				}
				else {
					$r{$j}->{$opt} = $val;
				}
			}
		}
	}
	return \%r;
}

sub htmlentities {
	my $_ = shift;
	s/&/&amp;/g;
	s/[""]/&quot;/g;
	s/</&lt;/g;
	s/>/&gt;/g;
	return $_;
}

sub colorByTarget {
	my $_ = shift;
	my $color = "transparent";
	if(defined $targetColor{$_}) {
		$color = $targetColor{$_};
	}
	if($color =~ /^[[:xdigit:]]{6}$/) {
		$color = "#$color";
	}
	return $color;
}

sub headPortByRankdir {
	my $rankdir = shift || $rankDirection;
	if($rankdir eq "TB") {
		return 'n';
	}
	elsif($rankdir eq "BT") {
		return  's';
	}
	else {
		return 0;
	}
}
sub tailPortByRankdir {
	my $rankdir = shift || $rankDirection;
	if($rankdir eq "RL") {
		return 'w';
	}
	else {
		return 'e';
	}
}

sub conditions2text {
	my %c = %{$_[0]};
	my %filter_hash = %{$_[1]};
	my @out;
	#return join ", ", map { sprintf "%s=%s", $_, $c{"all"}->{$_}; } grep { !defined $noDisplayCondition{$_}; } keys %{$c{"all"}};
	for my $neg (qw/positive negative/) {
		my $exclam = ($neg eq "negative") ? "!" : "";
		for my $opt (keys %{$c{$neg}}) {
			my $val = $c{$neg}->{$opt};
			my $str;
			next if defined $filter_hash{$opt};
			
			if($opt eq "dst" or $opt eq "src") {
				$val =~ s/\/32$//;
				$val =~ s/^0\.0\.0\.0\/.*/any/;
			}

			if(defined $val) {	$str = "$opt=$val"; }
			else {			$str = $opt; }
			if($opt eq "p") {	$str = uc $val; }
			if($opt eq "f") {	$str = "frag"; }
			
			if($opt eq "dst" and defined $c{$neg}->{"dport"}) {
				$str .= ":" . $c{$neg}->{"dport"};
			}
			if($opt eq "src" and defined $c{$neg}->{"sport"}) {
				$str .= ":" . $c{$neg}->{"sport"};
			}
			if(($opt eq "dport" and defined $c{$neg}->{"dst"}) or ($opt eq "sport" and defined $c{$neg}->{"src"})) {
				next;
			}
			
			push @out, $exclam.$str;
		}
	}
	return join "; ", @out;
}

sub action2text {
	my %r = %{$_[0]};
	my $short = $_[1];
	my @str;
	if($short) {
		if(! grep { $_ eq $r{"target"} } qw/DROP ACCEPT REJECT/
		   and !$uChain{$cTable}->{$r{"target"}}
		  ) {
			push @str, $r{"target"};
		}
	}
	else {
		if($terminatingTarget{ $r{"target"} }) {
			push @str, $r{"target"};
		}
		else {
			#push @str, $r{"calling"};
			push @str, $callName{$r{"call_type"}};
		}
	}
	for my $akey (keys %{$r{"action"}}) {
		my $val = $r{"action"}->{$akey};
		push @str, "$akey=$val";
	}
	return join " ", @str;
}

sub mk_nodeattribs {
	my %a = %{$_[0]};
	return join(",", map {
	    my $v = $a{$_};
	    my $q = ($v =~ /["",\\]/ and $v !~ /^</) ? "\"" : "";
	    sprintf "%s=$q%s$q", $_, $a{$_};
	} keys %a);
}

sub mk_edgeattribs {
	my %e = %{$_[0]};
	my @attr;
	push @attr, "color=".$callColor{$e{"call_type"}} if defined $callColor{$e{"call_type"}};
	push @attr, "style=".$callStyle{$e{"call_type"}} if defined $callStyle{$e{"call_type"}};
	push @attr, "dir=both", "arrowtail=tee" if $e{"call_type"} eq 'g';
	push @attr, "dir=both", "arrowtail=odot" if $e{"call_type"} eq 'P' and !$e{"tailNode_not_chain"};
	return join ",", @attr;
}

sub is_unconditional {
	my %r = %{$_[0]};
	if(scalar keys %{$r{"condition"}->{"all"}} == 0) {
		return 1;
	}
	return 0;
}






for(split/\n/, $ipt) {
	if(/^\*(\S+)/) {
		$cTable = $1;
	}
	elsif(/^:(\S+)\s+(-|[A-Z]+)/) {
		my $name = $1;
		my $pol = $2;
		if($pol eq "-") { $pol = "RETURN"; }
		
		$Policy{$cTable}->{$name} = $pol;
		@{$Fw{$cTable}->{$name}} = ();
		
		if($pol eq "RETURN") {
			$uChain{$cTable}->{$name} = 1;
		}
		else {
			$bChain{$cTable}->{$name} = 1;
		}
	}
	elsif(/^-A\s+(\S+)\s+(.*)/) {
		push @{$Fw{$cTable}->{$1}}, parseRuleStr($2);
	}
}


for my $Table (keys %Fw) {
	for my $Chain (keys $Fw{$Table}) {
		$last_rule = $Fw{$Table}->{$Chain}->[$#{$Fw{$Table}->{$Chain}}];
		if(not (defined $last_rule and is_unconditional($last_rule)) ) {
			my $pol = $Policy{$Table}->{$Chain};
			push @{$Fw{$Table}->{$Chain}}, {
				"call_type" => "P",
				"policy" => $pol,
				"target" => $pol,
			};
		}
	}
}


for my $Table (keys %Fw) {
	for my $Chain (keys $Fw{$Table}) {
		my @table;
		my $html_table;
		my $rule_num = 0;

		for my $Rule_ref (@{$Fw{$Table}->{$Chain}}) {
			$rule_num++;
			%Rule = %$Rule_ref;
			my $text = conditions2text($Rule{"condition"}, \%noDisplayCondition);
			if($text) {
				$cTable = $Table;
				$atext = action2text(\%Rule, 1);
				if($atext) {
					$text .= " $arrows{'s'} $atext";
				}
			}
			else {
				$text = action2text(\%Rule) || conditions2text($Rule{"condition"});
				if($text eq "RETURN") {
					$text = $arrows{lc substr $rankDirection, 0, 1} . " $text";
				}
			}
			push @table, {
				"port" => $rule_num,
				"bg" => colorByTarget($Rule{"target"}),
				"text" => $text,
			};
			if(defined $uChain{$Table}->{$Rule{"target"}}) {
				push @Edge, {
					"tailNode" => "$Table-$Chain",
					"tailPort" => $rule_num . ":" . tailPortByRankdir(),
					"headNode" => "$Table-" . $Rule{"target"},
					"headPort" => headPortByRankdir(),
					"call_type" => $Rule{"call_type"},
				};
			}
		}
		$PortsNum{$Table}->{$Chain} = $rule_num;

		$html_table = "<TABLE BORDER=\"0\" CELLBORDER=\"1\" CELLSPACING=\"0\">\n";
		$html_table .= sprintf "\t<TR><TD PORT=\"0\" BGCOLOR=\"grey\"><FONT POINT-SIZE=\"10\">%s</FONT><BR/><FONT POINT-SIZE=\"14\">%s</FONT></TD></TR>\n", $Table, $Chain;
		for my $r (@table) {
			my $str = htmlentities($r->{"text"});
			$html_table .= sprintf "\t<TR><TD PORT=\"%s\" BGCOLOR=\"%s\">%s</TD></TR>\n", $r->{"port"}, $r->{"bg"}, $str;
		}
		$html_table .= "</TABLE>";

		push @Node, {
			"name" => "$Table-$Chain",
			"attribute" => {
				"shape" => "none",
				"margin" => 0,
				"label" => "<".$html_table.">",
			},
		};
	}
}


for my $ref (@bChainFlow) {
	my($tail, $head) = @$ref;
	my %edge;
	$edge{"call_type"} = "P";
	if(ref $tail eq 'ARRAY') {
		$edge{"tailNode"} = $tail->[0] . "-" . $tail->[1];
		$edge{"tailPort"} = $PortsNum{$tail->[0]}->{$tail->[1]};
	}
	else {
		$edge{"tailNode"} = $tail;
		$edge{"tailNode_not_chain"} = 1;
	}
	if(ref $head eq 'ARRAY') {
		$edge{"headNode"} = $head->[0] . "-" . $head->[1];
		$edge{"headPort"} = headPortByRankdir();
	}
	else {
		$edge{"headNode"} = $head;
	}
	if(ref $tail ne 'ARRAY' and ref $head ne 'ARRAY') {
		$edge{"tailNode"} = $tail;
		$edge{"headNode"} = $head;
	}
	push @Edge, \%edge;
}

push @Node, { "name" => "routing_decision-1", "attribute" => {"shape"=>"diamond","margin"=>0,"label"=>"Routing\\nDecision"} },
	    { "name" => "routing_decision-2", "attribute" => {"shape"=>"diamond","margin"=>0,"label"=>"Routing\\nDecision"} },
	    { "name" => "network-1", "attribute" => {"shape"=>"trapezium","margin"=>0,"label"=>"Network","style"=>"filled","fillcolor"=>"yellow"} },
	    { "name" => "network-2", "attribute" => {"shape"=>"trapezium","margin"=>0,"label"=>"Network","style"=>"filled","fillcolor"=>"yellow"} },
	    { "name" => "local_process-1", "attribute" => {"shape"=>"trapezium","margin"=>0,"label"=>"Local\\nProcess","style"=>"filled","fillcolor"=>"yellow"} },
	    { "name" => "local_process-2", "attribute" => {"shape"=>"trapezium","margin"=>0,"label"=>"Local\\nProcess","style"=>"filled","fillcolor"=>"yellow"} };





print STDERR Dumper \%bChain, \%uChain, \%Policy, \%Fw, \@Node, \@Edge unless $quiet_output;


print "digraph \"Firewall\" {";
print "  rankdir=$rankDirection;";
print "  ranksep=2.0;";
print "  concentrate=true;";
print "  splines=$Splines;";
print "  node [fontsize=10,width=.1,height=.1,nodesep=2.0];";
for my $n (@Node) {
	printf "    \"%s\" [%s];\n", $n->{"name"}, mk_nodeattribs($n->{"attribute"});
}
print;
for my $e (@Edge) {
	defined $e->{"tailPort"} and $e->{"tailPort"} = ":" . $e->{"tailPort"};
	defined $e->{"headPort"} and $e->{"headPort"} = ":" . $e->{"headPort"};
	printf "    \"%s\"%s -> \"%s\"%s [%s];\n", $e->{"tailNode"}, $e->{"tailPort"}, $e->{"headNode"}, $e->{"headPort"}, mk_edgeattribs($e);
}
for my $ref (@sameRankHelper) {
	print "    { rank=same;";
	print "      \"" . join("-", @$_) . "\";" for @$ref;
	print "    }";
}
print "}";


