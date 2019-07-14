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
import hotp
import times

export hotp.HashFunctionType

type
  Totp* = ref object
    initialTime: float
    secret: string
    step, digits: int
    hashType: HashFunctionType

proc newTotp*(secret: string, initialTime: float, step, digits: int, hashType: HashFunctionType): Totp =
  result = Totp(
    secret: secret,
    initialTime: initialTime,
    step: step,
    digits: digits,
    hashType: hashType
  )

proc calculateT*(initialTime: float, step: int): int =
  result = int(floor((epochTime() - initialTime) / float(step)))

proc generate*(secret: string, t: int, digits: int, hashType: HashFunctionType): string =
  result = hotp.generate(secret, t, digits, hashType)

proc generate*(totp: Totp, currentTime: float): string =
  let t = calculateT(totp.initialTime, totp.step)
  result = generate(totp.secret, t, totp.digits, totp.hashType)
