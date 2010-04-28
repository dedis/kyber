
"""
Filename: settings.py
Description: Global settings constants for anon protocol.
"""

"""
FOR EMULAB TESTBED
"""

''' Your emulab username '''
EMULAB_USERNAME='FAKEUSER'
''' The address of your emulab network.  This will be appended
	to each node address in your address to create the full node
	address. '''
EMULAB_SUFFIX='.EXPERIMENT_NAME.PROJECT_NAME.emulab.net'
''' The dir where you have copied all of the implementation files '''
EMULAB_ROOT_DIR='/proj/PROJECT_NAME/exp/EXPERIMENT_NAME/DIR_TO_FILES'


"""
Directories for storing logs and data.  These names are RELATIVE
to the EMULAB_ROOT_DIR you specify above.  Make sure that these
directories exist before you try to run the implementation.
"""
DATA_DIR='data'
LOGS_DIR='logs'


"""
YALE INTERNAL USE ONLY
(For Yale's Zoo lab.)
"""
ZOO_USERNAME='FAKEUSER'
ZOO_SUBDIR='DIR_TO_FILES'


