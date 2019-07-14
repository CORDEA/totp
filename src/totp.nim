# Copyright 2019 Yoshihiro Tanaka
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

  # http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Yoshihiro Tanaka <contact@cordea.jp>
# date  : 2019-07-14

import hmac
import math
import times

type
  UnsupportedDigitLengthError = object of Exception

proc calculateT*(t0: float, step: int): int =
  result = int(floor((epochTime() - t0) / float(step)))

proc generate*(secret: string, t: int, digits: int): string =
  var text = $t
  while len(text) < 8:
    text = "0" & text
  echo text

  let hash = hmac_sha1(secret, text)
  let offset = hash[len(hash)-1] and 0xf
  let binary =
    (int(hash[offset] and 0x7f) shl 24) or
      (int(hash[offset+1] and 0xff) shl 16) or
      (int(hash[offset+2] and 0xff) shl 8) or
      int(hash[offset+3] and 0xff)
  var otp = 0
  case digits
  of 6:
    otp = binary mod 1000000
  of 7:
    otp = binary mod 10000000
  of 8:
    otp = binary mod 100000000
  else:
    discard

  if otp == 0:
    raise newException(UnsupportedDigitLengthError, "Unsupported number of digits.")

  result = $otp
  while len(result) < digits:
    result = "0" & result
