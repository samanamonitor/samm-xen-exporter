import logging
import sys
from sammxenexporter import SammXenExporter

if __name__ == "__main__":
    FORMAT = '%(asctime)s - %(levelname)s:%(funcName)s %(message)s'
    logging.basicConfig(stream=sys.stderr, format=FORMAT)
    config_file = 'config.json'
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    sxe = SammXenExporter()
    sxe.load_config(config_file)
    sxe.run()

