@echo on
IF EXIST "%programfiles(x86)%" (
	wflash2x64.exe imageo2v.rom /bb /rsmb %*
	) ELSE ( 
	wflash2.exe imageo2v.rom /bb /rsmb %*
	)
