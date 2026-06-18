// Copyright (c) 2012-2016, The CryptoNote developers, The Bytecoin developers
//
// This file is part of Karbo.
//
// Karbo is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Karbo is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with Karbo.  If not, see <http://www.gnu.org/licenses/>.

// This file previously held Currency::isFusionTransaction tests. Discrete removed
// fusion transactions entirely (only PQ transactions exist), so those tests —
// and the FusionTransactionBuilder helper they used — were deleted. The
// PQ transaction-shape / fee / emission rules are covered by the Pq* suites
// (tests/test_pq_validation.cpp, test_pq_chain.cpp).
