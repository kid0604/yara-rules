import "hash"

rule GandCrab_alt_1
{
	meta:
		description = "Detect the risk of GandCrab Rule 2"
		hash1 = "ce9c9917b66815ec7e5009f8bfa19ef3d2dfc0cf66be0b4b99b9bebb244d6706"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "tXujazajiyani voxazo. Wi wayepaxoli wuropiyenazizo fo. Cona leseyimucaye dupoxiyo. Nice mibehahasepa wudehukusidada garaterisovu" ascii
		$s2 = "Gihepipigudi sirabuzogasoji. Sorizo sexabonera. Muyokeza niboru kikekimuxu rupo vojurotavugoyi. Yi yugose kadohajedumiya. Bedase" ascii
		$s3 = " tixakehe. Reseyetasohora benusere vata kenevagume. Gedagu pegaleheruwago bukiredexuvuwa je. Yowujovu tuzudiposuxe zoyirudipu fo" ascii
		$s4 = "imarijoyaneye vetuwipu. Fe. Bedopiyo comu jiye ze. Josusutime vumavizaseha. Pezofogijuxo nucosegogili bobi xayogaci. Kuyi letozo" ascii
		$s5 = "**,,,," fullword ascii
		$s6 = "seyeruxiyehoxidecekajegexozaya gopegiyutusuwofobolikuhubu" fullword wide
		$s7 = "Jetewavasaloge" fullword wide
		$s8 = "vice zako wukewofeja vehe. Baji givihazi fuyacizogizanu. Gipayacucipi. Wetewavasa. Logeju xosidijoha ruxayo. Gorayo cicenehozogo" ascii
		$s9 = "zimosafodi dusepe. Jacudagemuva falo miseyicuwatita koneyepijo. Sudotakupovete mulavifiposo xohilujusucu fususabo. Henihideya di" ascii
		$s10 = "zumi gesakuki xoyefepuwahuje. Cugetutu. Nivileralu wafu jojoxaruku luraza punekuce. Dolape dubo. Jirehebeta jeda raguluyoda wohu" ascii
		$s11 = "444F4,F44" fullword ascii
		$s12 = "ale wufevujo kagomi haciceye. Yevaxudizera fasumatevakuvo kogumiwubo ta. Hutucozamevi jiharabeme bopobozeharu puyucite fuvukuyi." ascii
		$s13 = "44,,,,,,4b" fullword ascii
		$s14 = "jojukalo lijogagulucurukeyuroyupoheve mi" fullword wide
		$s15 = "YKuluye sepuhe zi mosafodidusepe jacudagemuva falomiseyicuwa titako neyepijosu dotakupo ve" fullword wide
		$s16 = "Yefepuwahuje cugetutu nivi le" fullword wide
		$s17 = " yeruxiyeho xide cekajegexoza. Yagopegi. Yutu suwofo bo. Likuhubujojuka lolijogagulucu. Ru keyuro yupohevelivu dubiyuyinaxo. Dey" ascii
		$s18 = "VUGOYIYIYUGOSEKADOHAJEDUMIYA" fullword wide
		$s19 = "XCJSEUPAVJ" fullword wide
		$s20 = "Eimnxjk" fullword ascii
		$s21 = "ikernel32.dll" fullword wide
		$s22 = "hulinowujovimuxatelo zabemaperetaboyazowa vituxifuyuyakixi" fullword ascii
		$s23 = "Va penoyotoretunurosacidutezajogu fatixiposapapabicu boyokopusidonoyododusahehu" fullword ascii
		$s24 = " Base Class Descriptor at (" fullword ascii
		$s25 = "ruxayogorayocice" fullword wide
		$s26 = "GDCB-DECRYPT.txt" wide
		$s27 = "culico yami" fullword ascii
		$s28 = "ReflectiveLoader" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 4 of them
}
