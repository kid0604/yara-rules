rule Email_Generic_PHP_Mailer_Script
{
	meta:
		Description = "Generic rule to identify potential emails sent from hacktool mailer scripts"
		Author = "Xylitol <xylitol@temari.fr>"
		date = "2020-05-11"
		description = "Generic rule to identify potential emails sent from hacktool mailer scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$donotwant1 = { FE ED FA CE }
		$donotwant2 = { FE ED FA CF }
		$donotwant3 = { CE FA ED FE }
		$donotwant4 = { CE FA ED FE }
		$donotwant5 = { 4D 5A 50 00 02 }
		$donotwant6 = { 53 75 62 6A 65 63 74 3A 20 25 73 }
		$legit1 = "(https://github.com/PHPMailer/PHPMailer)"
		$legit2 = "(phpmailer.sourceforge.net)"
		$legit3 = "X-Mailer: PHPMailer"
		$legit4 = "SimpleMailInvoker.php"
		$legit5 = "X-Mailer: SMF"
		$legit6 = "X-Mailer: phpBB3"
		$legit7 = "X-Mailer: PHP/Xooit"
		$legit8 = "X-Mailer: vBulletin"
		$legit9 = "X-Mailer: MediaWiki mailer"
		$legit10 = "X-Mailer: Drupal"
		$legit11 = "X-Mailer: osCommerce Mailer"
		$legit12 = "abuse@mailjet.com"
		$legit13 = "class.foxycart.transaction.php"
		$legit14 = "User-Agent: Roundcube Webmail"
		$legit15 = "User-Agent: SquirrelMail"
		$legit16 = "X-Source: /opt/cpanel/"
		$legit17 = { 58 2D 50 48 50 2D 4F 72 69 67 69 6E 61 74 69 6E 67 2D 53 63 72 69 70 74 3A 20 [1-6] 3A 70 6F 73 74 2E 70 68 70 28 [1-6] 29 }
		$legit18 = { 58 2D 50 48 50 2D 53 63 72 69 70 74 3A 20 [3-30] 2F 70 6F 73 74 2E 70 68 70 20 66 6F 72 20 }
		$eml1 = "From:"
		$eml2 = "To:"
		$eml3 = "Subject:"
		$mailer1 = /X-PHP-Originating-Script: ([\w\.]+(.*\.php))?/
		$mailer2 = /X-PHP-Script: ([\w\.\/]+\/(.*\.php))?/
		$mailer3 = /X-PHP-Filename: (\/[\w]+\/(.*\.php))?/

	condition:
		not any of ($donotwant*) and not any of ($legit*) and all of ($eml*) and 2 of ($mailer*)
}
