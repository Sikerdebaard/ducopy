# “Commons Clause” License Condition v1.0
#
# The Software is provided to you by the Licensor under the License, as defined below, subject to the following condition.
#
# Without limiting other conditions in the License, the grant of rights under the License will not include, and the License does not grant to you, the right to Sell the Software.
#
# For purposes of the foregoing, “Sell” means practicing any or all of the rights granted to you under the License to provide to third parties, for a fee or other consideration (including without limitation fees for hosting or consulting/ support services related to the Software), a product or service whose value derives, entirely or substantially, from the functionality of the Software. Any license notice or attribution required by the License must also include this Commons Clause License Condition notice.
#
# Software: ducopy
# License: MIT License
# Licensor: Thomas Phil
#
#
# MIT License
#
# Copyright (c) 2024 Thomas Phil
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
class ApiKeyGenerator:
    """
    Generates an API key based on board serial, MAC address, and time.
    """

    def transform_char(self, c1: str, c2: str) -> str:
        """
        Transforms two characters into a single character using XOR and ASCII adjustments.

        Args:
            c1 (str): First character for transformation.
            c2 (str): Second character for transformation.

        Returns:
            str: A single character result of the transformation.
        """
        result = (ord(c1) ^ ord(c2)) & 127
        if result < 48:
            result = (result % 26) + 97  # Lowercase letters
        elif 57 < result < 65:
            result = (result % 26) + 65  # Uppercase letters
        elif 90 < result < 97:
            result = (result % 10) + 48  # Digits
        elif result > 122:
            result = (result % 10) + 48  # Digits
        return chr(result)

    def generate_api_key(self, board_serial: str, mac_address: str, time: int) -> str:
        """
        Generates a unique API key based on the MAC address, board serial, and time.

        Args:
            board_serial (str): The serial number of the board.
            mac_address (str): The MAC address of the device.
            time (int): The Unix timestamp for the generation process.

        Returns:
            str: The generated API key as a 64-character string.
        """
        key_template = list("n4W2lNnb2IPnfBrXwSTzTlvmDvsbemYRvXBRWrfNtQJlMiQ8yPVRmGcoPd7szSu2")

        # Transforming key with mac_address
        for i in range(min(len(mac_address), 32)):
            key_template[i] = self.transform_char(key_template[i], mac_address[i])

        # Transforming key with board_serial
        for i in range(min(len(board_serial), 32)):
            key_template[i + 32] = self.transform_char(key_template[i + 32], board_serial[i])

        # Adjust key based on time
        adjusted_time = time // 86400
        for i in range(16):
            if (adjusted_time & (1 << i)) != 0:
                idx = i * 4
                key_template[idx] = self.transform_char(key_template[idx], key_template[i * 2 + 32])
                key_template[idx + 1] = self.transform_char(key_template[idx + 1], key_template[63 - (i * 2)])
                key_template[idx + 2] = self.transform_char(key_template[idx], key_template[idx + 1])
                key_template[idx + 3] = self.transform_char(key_template[idx + 1], key_template[idx + 2])

        return "".join(key_template)
