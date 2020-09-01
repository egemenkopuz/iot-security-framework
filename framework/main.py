from engine.setup import Setup
from engine.core import Core

if __name__ == '__main__':
    try:
        Setup().start()
        Core().start()
    except Exception as e:
        print(f'FATAL ERROR: {e}')