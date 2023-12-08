rule EQGRP_1212
{
	meta:
		description = "Detects tool from EQGRP toolset - file 1212.pl"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-15"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "if (!(($srcip,$dstip,$srcport,$dstport) = ($line=~/^([a-f0-9]{8})([a-f0-9]{8})([a-f0-9]{4})([a-f0-9]{4})$/)))" fullword ascii
		$s2 = "$ans=\"$srcip:$srcport -> $dstip:$dstport\";" fullword ascii
		$s3 = "return \"ERROR:$line is not a valid port\";" fullword ascii
		$s4 = "$dstport=hextoPort($dstport);" fullword ascii
		$s5 = "sub hextoPort" fullword ascii
		$s6 = "$byte_table{\"$chars[$sixteens]$chars[$ones]\"}=$i;" fullword ascii

	condition:
		filesize <6KB and 4 of them
}
