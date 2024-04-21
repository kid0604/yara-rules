import "pe"

rule sig_17333_sc
{
	meta:
		description = "17333 - file sc.ps1"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
		date = "2023-02-03"
		hash1 = "ac933ffc337d13b276e6034d26cdec836f03d90cb6ac7af6e11c045eeae8cc05"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "screenshot C:\\users\\Public\\module\\sc.png" fullword ascii
		$s2 = "$screen = [System.Windows.Forms.Screen]::AllScreens;" fullword ascii
		$s3 = "if($workingAreaX -gt $item.WorkingArea.X)" fullword ascii
		$s4 = "if($item.Bounds.Height -gt $height)" fullword ascii
		$s5 = "if($workingAreaY -gt $item.WorkingArea.Y)" fullword ascii
		$s6 = "$width = $width + $item.Bounds.Width;" fullword ascii
		$s7 = "$workingAreaX = 0;" fullword ascii
		$s8 = "$height = $item.Bounds.Height;" fullword ascii
		$s9 = "$workingAreaY = 0;" fullword ascii
		$s10 = "$workingAreaY = $item.WorkingArea.Y;" fullword ascii
		$s11 = "$bounds = [Drawing.Rectangle]::FromLTRB($workingAreaX, $workingAreaY, $width, $height);" fullword ascii
		$s12 = "$graphics = [Drawing.Graphics]::FromImage($bmp);" fullword ascii
		$s13 = "$workingAreaX = $item.WorkingArea.X;" fullword ascii
		$s14 = "foreach ($item in $screen)" fullword ascii
		$s15 = "function screenshot($path)" fullword ascii
		$s16 = "$bmp = New-Object Drawing.Bitmap $width, $height;" fullword ascii
		$s17 = "$bmp.Dispose();" fullword ascii
		$s18 = "$bmp.Save($path);" fullword ascii
		$s19 = "$graphics.Dispose();" fullword ascii
		$s20 = "[void] [System.Reflection.Assembly]::LoadWithPartialName(\"System.Drawing\")" fullword ascii

	condition:
		uint16(0)==0x525b and filesize <3KB and 8 of them
}
