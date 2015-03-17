/*
xxHashSharp - A pure C# implementation of xxhash
Copyright (C) 2014, Seok-Ju, Yun. (https://github.com/noricube/xxHashSharp)
Original C Implementation Copyright (C) 2012-2014, Yann Collet. (https://code.google.com/p/xxhash/)
BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above
      copyright notice, this list of conditions and the following
      disclaimer in the documentation and/or other materials provided
      with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

using System;
using System.Security.Cryptography;

namespace xxHashSharp
{
    public class xxHash : HashAlgorithm
    {
        private struct XXH_State
        {
            public ulong total_len;
            public uint seed;
            public uint v1;
            public uint v2;
            public uint v3;
            public uint v4;
            public int memsize;
            public byte[] memory;
        };

        private const uint PRIME32_1 = 2654435761U;
        private const uint PRIME32_2 = 2246822519U;
        private const uint PRIME32_3 = 3266489917U;
        private const uint PRIME32_4 = 668265263U;
        private const uint PRIME32_5 = 374761393U;

        private XXH_State _state;

        private readonly uint seed;

        public xxHash() : this(0)
        {
        }

        public xxHash(uint seed)
        {
            this.seed = seed;
            Initialize();
        }

        public override void Initialize()
        {
            _state.seed = seed;
            _state.v1 = seed + PRIME32_1 + PRIME32_2;
            _state.v2 = seed + PRIME32_2;
            _state.v3 = seed + 0;
            _state.v4 = seed - PRIME32_1;
            _state.total_len = 0;
            _state.memsize = 0;
            _state.memory = new byte[16];
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            int index = ibStart;

            _state.total_len += (uint)cbSize;

            if (_state.memsize + cbSize < 16) // 버퍼 + 입력길이가 16바이트 이하일경우 버퍼에 저장만 해둔다
            {
                Buffer.BlockCopy(array, ibStart, _state.memory, _state.memsize, cbSize);
                _state.memsize += cbSize;
                return;
            }

            if (_state.memsize > 0) // 이전데이터가 남아있을경우 먼저 처리한다.
            {
                Buffer.BlockCopy(array, ibStart, _state.memory, _state.memsize, 16 - _state.memsize);

                _state.v1 = CalculateSubHash(_state.v1, _state.memory, index);
                index += 4;
                _state.v2 = CalculateSubHash(_state.v2, _state.memory, index);
                index += 4;
                _state.v3 = CalculateSubHash(_state.v3, _state.memory, index);
                index += 4;
                _state.v4 = CalculateSubHash(_state.v4, _state.memory, index);

                index = 0;
                _state.memsize = 0;
            }

            if (index <= cbSize - 16)
            {
                int limit = cbSize - 16;
                uint v1 = _state.v1;
                uint v2 = _state.v2;
                uint v3 = _state.v3;
                uint v4 = _state.v4;

                do
                {
                    v1 = CalculateSubHash(v1, array, index);
                    index += 4;
                    v2 = CalculateSubHash(v2, array, index);
                    index += 4;
                    v3 = CalculateSubHash(v3, array, index);
                    index += 4;
                    v4 = CalculateSubHash(v4, array, index);
                    index += 4;
                }
                while (index <= limit);

                _state.v1 = v1;
                _state.v2 = v2;
                _state.v3 = v3;
                _state.v4 = v4;
            }

            if (index < cbSize)
            {
                Buffer.BlockCopy(array, index, _state.memory, 0, cbSize - index);
                _state.memsize = cbSize - index;
            }
        }

        protected override byte[] HashFinal()
        {
            uint h32;
            int index = 0;
            if (_state.total_len >= 16)
            {
                h32 = RotateLeft(_state.v1, 1) + RotateLeft(_state.v2, 7) + RotateLeft(_state.v3, 12) + RotateLeft(_state.v4, 18);
            }
            else
            {
                h32 = _state.seed + PRIME32_5;
            }

            h32 += (UInt32) _state.total_len;

            while (index <= _state.memsize - 4)
            {
                h32 += BitConverter.ToUInt32(_state.memory, index)*PRIME32_3;
                h32 = RotateLeft(h32, 17)*PRIME32_4;
                index += 4;
            }

            while (index < _state.memsize)
            {
                h32 += _state.memory[index]*PRIME32_5;
                h32 = RotateLeft(h32, 11)*PRIME32_1;
                index++;
            }

            h32 ^= h32 >> 15;
            h32 *= PRIME32_2;
            h32 ^= h32 >> 13;
            h32 *= PRIME32_3;
            h32 ^= h32 >> 16;

            return BitConverter.GetBytes(h32);
        }

        private static uint CalculateSubHash(uint value, byte[] bufer, int index)
        {
            uint v = BitConverter.ToUInt32(bufer, index);
            value += v*PRIME32_2;
            value = RotateLeft(value, 13);
            value *= PRIME32_1;
            return value;
        }

        private static uint RotateLeft(uint value, int count)
        {
            return (value << count) | (value >> (32 - count));
        }
    }
}
