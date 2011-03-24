mac:QMAKE_MACOSX_DEPLOYMENT_TARGET = 10.3

exists(crypto.prf) {
	# our apps should build against the qca in this tree
	include(crypto.prf)
} else {
	# attempt to use system-wide qca
	CONFIG *= crypto
}
