{-# OPTIONS_HADDOCK hide #-}

-- |
-- Module: Data.Barrier
-- Copyright: (c) 2026 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- An optimisation barrier for constant-time code.

module Data.Barrier (
    barrier
  ) where

import Data.Word (Word8)

-- | Identity on 'Word8', but opaque to the optimiser. A constant-time
--   accumulate-then-compare (e.g. an OR-fold of bytewise XORs, tested
--   against zero) routes its accumulator through this before the
--   zero-test, so the compiler cannot recognise it as an array-equality
--   test and lower it to a short-circuiting byte comparison (which would
--   leak the mismatch position).
--
--   Both properties are required and must not be \"tidied\" away:
--
--     * @NOINLINE@ -- if GHC inlines it, the LLVM backend regains the
--       accumulator's definition and short-circuits again.
--     * a /separate/ module -- a caller then compiles @barrier@ to an
--       external call it cannot see through. Inline it into the caller
--       and the barrier is gone.
--
barrier :: Word8 -> Word8
barrier x = x
{-# NOINLINE barrier #-}
