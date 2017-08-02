package scorex.crypto.hash

import ove.crypto.digest.Blake2b.Digest
import scorex.utils.LittleEndianBytes._

object Equihash {
 def hashNonce(digest: Digest, nonce: BigInt): Digest = {
   for (i <- 0 to 7) digest.update(leIntToByteArray((nonce >> 32*i).intValue()))
   digest
 }

// todo def hash_xi(digest, xi):

// todo def count_zeroes(h):

// todo def has_collision(ha, hb, i, l):

// todo def distinct_indices(a, b):

// todo def xor(ha, hb):

  // todo Implementation of Basic Wagner's algorithm for the GBP
  private[hash] def gbpBasic(digest: Digest, n: Int, k: Int): Seq[Seq[Int]] = ???
//  1) Generate first list
//  X_i = H(I||V||x_i)
//  3) Repeat step 2 until 2n/(k+1) bits remain
//  2a) Sort the list
//  2b) Find next set of unordered pairs with collisions on first n/(k+1) bits
//  2c) Store tuples (X_i ^ X_j, (i, j)) on the table
//  Check that there are no duplicate indices in tuples i and j
//  2d) Drop this set
//  2e) Replace previous list with new list
//  k+1) Find a collision on last 2n(k+1) bits

// todo def block_hash(prev_hash, nonce, soln):

// todo def print_hash(h)

// todo def validate_params(n, k)
}
