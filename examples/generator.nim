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

import os
import times
import ../src/totp

const Secret = "01234567890123456789"

# Base32 encoded secret
# Used in google authenticator.
const EncodedSecret = "GAYTEMZUGU3DOOBZGAYTEMZUGU3DOOBZ"

let gen = newTotp(Secret, 0, 30, 6, TypeSha1)
for i in 1..10:
  echo gen.generate(epochTime())
  sleep(30 * 1000)
