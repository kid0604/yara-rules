rule FVEY_ShadowBroker_Auct_Dez16_Strings
{
	meta:
		description = "String from the ShodowBroker Files Screenshots - Dec 2016"
		author = "Florian Roth (Nextron Systems)"
		score = 60
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		date = "2016-12-17"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "bs.ratload" fullword ascii
		$s2 = "Auditcleaner" fullword ascii
		$s3 = "bll.perlbind" fullword ascii
		$s4 = "bll.perlcallback" fullword ascii
		$s5 = "bll.telnet" fullword ascii
		$s6 = "bll.tnc.gr" fullword ascii
		$s7 = "clean_wtmps.py" fullword ascii
		$s8 = "cmsex.auto" fullword ascii
		$s9 = "cottonaxe" fullword ascii
		$s10 = "dectelnet.sh" fullword ascii
		$s11 = "elatedmonkey" fullword ascii
		$s12 = "electricslide.pl" fullword ascii
		$s13 = "endlessdonut" fullword ascii
		$s14 = "solaris8shellcode" fullword ascii
		$s15 = "solaris9shellcode" fullword ascii
		$s16 = "solaris10shellcode" fullword ascii
		$s17 = "ys.ratload.sh" fullword ascii
		$elf1 = "catflap" fullword ascii
		$elf2 = "charm_penguin" fullword ascii
		$elf3 = "charm_hammer" fullword ascii
		$elf4 = "charm_saver" fullword ascii
		$elf5 = "dampcrowd" fullword ascii
		$elf7 = "dubmoat" fullword ascii
		$elf8 = "ebbshave" fullword ascii
		$elf9 = "eggbasket" fullword ascii
		$elf10 = "toffeehammer" fullword ascii
		$elf11 = "enemyrun" fullword ascii
		$elf12 = "envoytomato" fullword ascii
		$elf13 = "expoxyresin" fullword ascii
		$elf14 = "estopmoonlit" fullword ascii
		$elf15 = "linux-exactchange" fullword ascii
		$elf17 = "ghost_sparc" fullword ascii
		$elf18 = "jackpop" fullword ascii
		$elf19 = "orleans_stride" fullword ascii
		$elf20 = "prokserver" fullword ascii
		$elf21 = "seconddate" fullword ascii
		$elf22 = "shentysdelight" fullword ascii
		$elf23 = "skimcountry" fullword ascii
		$elf24 = "slyheretic" fullword ascii
		$elf25 = "stoicsurgeon" fullword ascii
		$elf26 = "strifeworld" fullword ascii
		$elf27 = "suaveeyeful" fullword ascii
		$elf28 = "suctionchar" fullword ascii
		$elf29 = "vs.attack.linux" fullword ascii
		$pe1 = "charm_razor" fullword ascii wide
		$pe2 = "charm_saver" fullword ascii wide
		$pe3 = "ghost_x86" fullword ascii wide

	condition:
		( uint16(0)==0x457f and 1 of ($elf*)) or ( uint16(0)==0x5a4d and 1 of ($pe*)) or 1 of ($s*)
}
