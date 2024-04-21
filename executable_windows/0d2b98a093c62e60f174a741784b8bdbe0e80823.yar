rule bumblebee_13842_n23_dll
{
	meta:
		description = "BumbleBee - file n23.dll"
		author = "The DFIR Report via yarGen Rule Generator"
		reference = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
		date = "2022-11-13"
		hash1 = "65a9b1bcde2c518bc25dd9a56fd13411558e7f24bbdbb8cb92106abbc5463ecf"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "scratched echo billion ornament transportation heedless should sandwiches hypothesis medicine strict thus sincere fight nourishm" ascii
		$s2 = "omu164ta8.dll" fullword ascii
		$s3 = "eadlight hours reins straightforward comfortable greeting notebook production nearby rung oven plus applet ending snapped enquir" ascii
		$s4 = "board blank convinced scuba mean alive perry character headquarters comma diana ornament workshop hot duty victorious bye expres" ascii
		$s5 = " compared opponent pile sky entitled balance valuable list ay duster tyre bitterly margaret resort valuer get conservative contr" ascii
		$s6 = "ivance pay clergyman she sleepy investigation used madame rock logic suffocate pull stated comparatively rowing abode enclosed h" ascii
		$s7 = " purple salvation dudley gaze requirement headline defective waiter inherent frightful night diary slang laurie bugs kazan annou" ascii
		$s8 = "nced apparently determined among come invited be goodwill tally crowded chances selfish duchess reel five peaceful offer spirits" ascii
		$s9 = "scratched echo billion ornament transportation heedless should sandwiches hypothesis medicine strict thus sincere fight nourishm" ascii
		$s10 = "s certificate breeze temporary according peach effected excuse preceding reaction channel bring short beams scheme gosh endless " ascii
		$s11 = "rtificial poke reassure diploma potentially " fullword ascii
		$s12 = "led spree confer belly rejection glide speaker wren do create evenings according cultivation concentration overcoat presume feed" ascii
		$s13 = "EgEEddEfhkdddEdfkEeddjgjehdjidhkdkeiekEeggdijhjidgkfigEgggdjkhkjkedEigifefdfhEjgghgEhjkeihifdhEEdgifefgkkEfEijhkhkhidddEdhgidfkE" ascii
		$s14 = "kgfjjjEEgkdiehfeEjihkfEeididdeEjhggEjedhdfEjiddgEgghejEidEfEEfgfjfhdghfddfihfidfEedikfdfjkiffkjiijiiijdhgghekhkegkidkgfjijhkiigg" ascii
		$s15 = "eekgEeideheghidkkEkkfkjikhiEhiefggdkhifdgEhhdEkkEkgjdEjjeEjhjhihfdgEdEidigefhhikdgdfEEdjEeggiEdfkdEdiEffdddkgikhhkihigEhjEdehieh" ascii
		$s16 = "eddEfefEEd" ascii
		$s17 = "hiefgfgkdfhgEdhEEgfhfegiiekgkdheihfjjhdeediefEkekdgeihhdfhhgjjiddjehgEhigEkEiEghejfidgjkdjidfkkfjEkfidfdiihkkEdEkEjjkEghfEdiihgE" ascii
		$s18 = "kfifkfkgdgdfhefdfejjdjigEhghidiiEekeEidEhghijgfkgkkedeeiggeEdhddkdhgigdjEihjiEjkgjjEefedfhidjkEjfghfjfdfdEjhkjjddjEfdgkEEikifdhE" ascii
		$s19 = "dedkdeeeeefgdEgfkkiEEfidikkffgighgEfiEEidgehdeiEhhjhjgiEdfkjihEgdgdefgkEfigdfedijhejEgdhkEdifEehifgdhddhfjghjfiifdhiigedggEdikeE" ascii
		$s20 = "efigfkfkkkfkdifiEhkhjkiejjidgkEfhEfehidhEfekgejgefEjEgdgefgidjjfdkjEfgfEigijhidideEEffjefkkkjjeeigggiighdddEddgegjEfEffjjjiddiEk" ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 1 of ($x*) and 4 of them
}
