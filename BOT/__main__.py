import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from core import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
