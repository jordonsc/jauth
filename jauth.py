#!/usr/bin/env python3

import sys

from auth import HOTP

h = HOTP()
code = h.generate_code_from_time(sys.argv[1])
print(code[0])
