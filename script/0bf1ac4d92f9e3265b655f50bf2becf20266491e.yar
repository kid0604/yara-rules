rule dump_sales_order
{
	meta:
		description = "Detects potential dumping of sales order data from Magento"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$ = "../../../../../../app/Mage.php'; Mage::app(); var_dump(Mage::getModel('sales/order')"

	condition:
		any of them
}
