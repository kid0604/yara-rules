rule marcher_v2
{
	meta:
		description = "This rule detects a new variant of Marcher"
		sample = "27c3b0aaa2be02b4ee2bfb5b26b2b90dbefa020b9accc360232e0288ac34767f"
		author = "Antonio S. <asanchez@koodous.com>"
		source = "https://analyst.koodous.com/rulesets/1301"
		os = "windows"
		filetype = "executable"

	strings:
		$a = /assets\/[a-z]{1,12}.datPK/
		$b = "mastercard_img"
		$c = "visa_verifed"

	condition:
		all of them
}
