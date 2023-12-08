import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_Binary_Embedded_Crypto_Wallet_Browser_Extension_IDs
{
	meta:
		author = "ditekSHen"
		description = "Detect binaries embedding considerable number of cryptocurrency wallet browser extension IDs."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii wide nocase
		$s2 = "fhbohimaelbohpjbbldcngcnapndodjp" ascii wide nocase
		$s3 = "ffnbelfdoeiohenkjibnmadjiehjhajb" ascii wide nocase
		$s4 = "jbdaocneiiinmjbjlgalhcelgbejmnid" ascii wide nocase
		$s5 = "afbcbjpbpfadlkmhmclhkeeodmamcflc" ascii wide nocase
		$s6 = "hnfanknocfeofbddgcijnmhnfnkdnaad" ascii wide nocase
		$s7 = "hpglfhgfnhbgpjdenjgmdgoeiappafln" ascii wide nocase
		$s8 = "blnieiiffboillknjnepogjhkgnoapac" ascii wide nocase
		$s9 = "cjelfplplebdjjenllpjcblmjkfcffne" ascii wide nocase
		$s10 = "fihkakfobkmkjojpchpfgcmhfjnmnfpi" ascii wide nocase
		$s11 = "kncchdigobghenbbaddojjnnaogfppfj" ascii wide nocase
		$s12 = "amkmjjmmflddogmhpjloimipbofnfjih" ascii wide nocase
		$s13 = "nlbmnnijcnlegkjjpcfjclmcfggfefdm" ascii wide nocase
		$s14 = "nanjmdknhkinifnkgdcggcfnhdaammmj" ascii wide nocase
		$s15 = "nkddgncdjgjfcddamfgcmfnlhccnimig" ascii wide nocase
		$s16 = "fnjhmkhhmkbjkkabndcnnogagogbneec" ascii wide nocase
		$s17 = "cphhlgmgameodnhkjdmkpanlelnlohao" ascii wide nocase
		$s18 = "nhnkbkgjikgcigadomkphalanndcapjk" ascii wide nocase
		$s19 = "kpfopkelmapcoipemfendmdcghnegimn" ascii wide nocase
		$s20 = "aiifbnbfobpmeekipheeijimdpnlpgpp" ascii wide nocase
		$s21 = "dmkamcknogkgcdfhhbddcghachkejeap" ascii wide nocase
		$s22 = "fhmfendgdocmcbmfikdcogofphimnkno" ascii wide nocase
		$s23 = "cnmamaachppnkjgnildpdmkaakejnhae" ascii wide nocase
		$s24 = "jojhfeoedkpkglbfimdfabpdfjaoolaf" ascii wide nocase
		$s25 = "flpiciilemghbmfalicajoolhkkenfel" ascii wide nocase
		$s26 = "nknhiehlklippafakaeklbeglecifhad" ascii wide nocase
		$s27 = "hcflpincpppdclinealmandijcmnkbgn" ascii wide nocase
		$s28 = "ookjlbkiijinhpmnjffcofjonbfbgaoc" ascii wide nocase
		$s29 = "mnfifefkajgofkcjkemidiaecocnkjeh" ascii wide nocase
		$s30 = "lodccjjbdhfakaekdiahmedfbieldgik" ascii wide nocase
		$s31 = "Ijmpgkjfkbfhoebgogflfebnmejmfbml" ascii wide nocase
		$s32 = "lkcjlnjfpbikmcmbachjpdbijejflpcm" ascii wide nocase
		$s33 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide nocase
		$s34 = "bcopgchhojmggmffilplmbdicgaihlkp" ascii wide nocase
		$s35 = "klnaejjgbibmhlephnhpmaofohgkpgkd" ascii wide nocase
		$s36 = "aeachknmefphepccionboohckonoeemg" ascii wide nocase
		$s37 = "dkdedlpgdmmkkfjabffeganieamfklkm" ascii wide nocase
		$s38 = "nlgbhdfgdhgbiamfdfmbikcdghidoadd" ascii wide nocase
		$s39 = "onofpnbbkehpmmoabgpcpmigafmmnjhl" ascii wide nocase
		$s40 = "cihmoadaighcejopammfbmddcmdekcje" ascii wide nocase
		$s41 = "cgeeodpfagjceefieflmdfphplkenlfk" ascii wide nocase
		$s42 = "pdadjkfkgcafgbceimcpbkalnfnepbnk" ascii wide nocase
		$s43 = "acmacodkjbdgmoleebolmdjonilkdbch" ascii wide nocase
		$s44 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide nocase
		$s45 = "fhilaheimglignddkjgofkcbgekhenbh" ascii wide nocase
		$s46 = "mgffkfbidihjpoaomajlbgchddlicgpn" ascii wide nocase
		$s47 = "hmeobnfnfcmdkdcmlblgagmfpfboieaf" ascii wide nocase
		$s48 = "lpfcbjknijpeeillifnkikgncikgfhdo" ascii wide nocase
		$s49 = "dngmlblcodfobpdpecaadgfbcggfjfnm" ascii wide nocase
		$s50 = "bhhhlbepdkbapadjdnnojkbgioiodbic" ascii wide nocase
		$s51 = "jnkelfanjkeadonecabehalmbgpfodjm" ascii wide nocase
		$s52 = "jhgnbkkipaallpehbohjmkbjofjdmeid" ascii wide nocase
		$s53 = "jnlgamecbpmbajjfhmmmlhejkemejdma" ascii wide nocase
		$s54 = "kkpllkodjeloidieedojogacfhpaihoh" ascii wide nocase
		$s55 = "mcohilncbfahbmgdjkbpemcciiolgcge" ascii wide nocase
		$s56 = "gjagmgiddbbciopjhllkdnddhcglnemk" ascii wide nocase
		$s57 = "kmhcihpebfmpgmihbkipmjlmmioameka" ascii wide nocase
		$s58 = "phkbamefinggmakgklpkljjmgibohnba" ascii wide nocase
		$s59 = "lpilbniiabackdjcionkobglmddfbcjo" ascii wide nocase
		$s60 = "cjmkndjhnagcfbpiemnkdpomccnjblmj" ascii wide nocase
		$s61 = "aijcbedoijmgnlmjeegjaglmepbmpkpi" ascii wide nocase
		$s62 = "efbglgofoippbgcjepnhiblaibcnclgk" ascii wide nocase
		$s63 = "odbfpeeihdkbihmopkbjmoonfanlbfcl" ascii wide nocase
		$s64 = "fnnegphlobjdpkhecapkijjdkgcjhkib" ascii wide nocase
		$s65 = "aodkkagnadcbobfpggfnjeongemjbjca" ascii wide nocase
		$s66 = "akoiaibnepcedcplijmiamnaigbepmcb" ascii wide nocase
		$s67 = "ejbalbakoplchlghecdalmeeeajnimhm" ascii wide nocase
		$s68 = "dfeccadlilpndjjohbjdblepmjeahlmm" ascii wide nocase
		$s69 = "kjmoohlgokccodicjjfebfomlbljgfhk" ascii wide nocase
		$s70 = "ajkhoeiiokighlmdnlakpjfoobnjinie" ascii wide nocase
		$s71 = "fplfipmamcjaknpgnipjeaeeidnjooao" ascii wide nocase
		$s72 = "niihfokdlimbddhfmngnplgfcgpmlido" ascii wide nocase
		$s73 = "obffkkagpmohennipjokmpllocnlndac" ascii wide nocase
		$s74 = "kfocnlddfahihoalinnfbnfmopjokmhl" ascii wide nocase
		$s75 = "infeboajgfhgbjpjbeppbkgnabfdkdaf" ascii wide nocase
		$s76 = "{530f7c6c-6077-4703-8f71-cb368c663e35}.xpi" ascii wide nocase
		$s77 = "ronin-wallet@axieinfinity.com.xpi" ascii wide nocase
		$s78 = "webextension@metamask.io.xpi" ascii wide nocase
		$s79 = "{5799d9b6-8343-4c26-9ab6-5d2ad39884ce}.xpi" ascii wide nocase
		$s80 = "{aa812bee-9e92-48ba-9570-5faf0cfe2578}.xpi" ascii wide nocase
		$s81 = "{59ea5f29-6ea9-40b5-83cd-937249b001e1}.xpi" ascii wide nocase
		$s82 = "{d8ddfc2a-97d9-4c60-8b53-5edd299b6674}.xpi" ascii wide nocase
		$s83 = "{7c42eea1-b3e4-4be4-a56f-82a5852b12dc}.xpi" ascii wide nocase
		$s84 = "{b3e96b5f-b5bf-8b48-846b-52f430365e80}.xpi" ascii wide nocase
		$s85 = "{eb1fb57b-ca3d-4624-a841-728fdb28455f}.xpi" ascii wide nocase
		$s86 = "{76596e30-ecdb-477a-91fd-c08f2018df1a}.xpi" ascii wide nocase
		$s87 = "ejjladinnckdgjemekebdpeokbikhfci" ascii wide nocase
		$s88 = "bgpipimickeadkjlklgciifhnalhdjhe" ascii wide nocase
		$s89 = "epapihdplajcdnnkdeiahlgigofloibg" ascii wide nocase
		$s90 = "aholpfdialjgjfhomihkjbmgjidlcdno" ascii wide nocase
		$s91 = "egjidjbpglichdcondbcbdnbeeppgdph" ascii wide nocase
		$s92 = "pnndplcbkakcplkjnolgbkdgjikjednm" ascii wide nocase
		$s93 = "gojhcdgcpbpfigcaejpfhfegekdgiblk" ascii wide nocase

	condition:
		( uint16(0)==0x5a4d and 6 of them ) or (12 of them )
}
