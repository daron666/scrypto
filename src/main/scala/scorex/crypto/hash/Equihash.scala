package scorex.crypto.hash

import com.google.common.primitives.Bytes
import org.slf4j.LoggerFactory
import ove.crypto.digest.Blake2b.{Digest, Engine}
import scorex.utils.LittleEndianBytes._

import scala.collection.mutable.ArrayBuffer

object Equihash {
  def hashNonce(digest: Digest, nonce: BigInt): Digest = {
    for (i <- 0 to 7) digest.update(leIntToByteArray((nonce >> 32 * i).intValue()))
    digest
  }

  def hashXi(digest: Engine, xi: Int): Engine = {
    digest.update(leIntToByteArray(xi))
    digest
  }

  def countZeroes(bytes: Array[Byte]): Int = {
    val byteSize = 8
    (0 until byteSize * bytes.size).foldLeft(0) {
      case (res, i) if (bytes(i / byteSize) << i % byteSize & 0x80) == 0 => res + 1
      case (res, _) => res
    }
  }

  def hasCollision(ha: Array[Byte], hb: Array[Byte], i: Int, lenght: Int): Boolean = {
    ((i - 1) * lenght / 8 until i * lenght / 8).forall(j => ha(j) == hb(j))
  }

  def distinctIndices(a: Set[Int], b: Set[Int]): Boolean = !a.exists(b)

  def xor(ha: Array[Byte], hb: Array[Byte]): Array[Byte] = {
    for {(a, b) <- ha.zip(hb)} yield (a ^ b).toByte
  }

  private val log = LoggerFactory.getLogger(getClass)

  // todo Implementation of Basic Wagner's algorithm for the GBP
  private[hash] def gbpBasic(digest: Digest, n: Int, k: Int): Seq[Seq[Int]] = {
    val collisionLength = n / (k + 1)
    log.debug("Generating first list")
    //  1) Generate first list
    var X = ArrayBuffer.empty[(Array[Byte], Set[Int])]
    for {i <- 0 until Math.pow(2, collisionLength + 1).toInt} {
      //  X_i = H(I||V||x_i)
      val currDigest = digest.clone()
      hashXi(currDigest, i)
      val d = currDigest.digest()
      val p = (d, Set(i))
      X += p
    }

    //  3) Repeat step 2 until 2n/(k+1) bits remain
    for (i <- 1 until k) {
      log.debug(s"Round $i")

      //  2a) Sort the list
      log.debug("- Sorting list")
      X = X.sortBy(_._1.toIterable)
      //      if (log.isDebugEnabled) {
      //    for Xi in X[-32:]:
      //    print '%s %s' % (print_hash(Xi[0]), Xi[1])
      //      }

      log.debug("- Finding collisions")
      var Xc = ArrayBuffer.empty[(Array[Byte], Set[Int])]
      while (X.nonEmpty) {
        //  2b) Find next set of unordered pairs with collisions on first n/(k+1) bits
        val j = (1 until X.size).find(j => !hasCollision(X.last._1, X(X.size - 1 - j)._1, i, collisionLength)).getOrElse(X.size)

        //  2c) Store tuples (X_i ^ X_j, (i, j)) on the table
        for {
          l <- 0 until j - 1
          m <- l + 1 until j
        } {
          val X1l = X(X.size - 1 - l)
          val X1m = X(X.size - 1 - m)
          //  Check that there are no duplicate indices in tuples i and j
          if (distinctIndices(X1l._2, X1m._2)) {
            val concat = if (X1l._2(0) < X1m._2(0)) {
              X1l._2 ++ X1m._2
            } else {
              X1m._2 ++ X1l._2
            }
            val p = (xor(X1l._1, X1m._1), concat)
            Xc += p
          }
        }

        X = X.take(X.size - j)
      }
      //  2e) Replace previous list with new list
      X = Xc
    }

    log.debug("Final round:")
    log.debug("- Sorting list")

    //    if DEBUG and VERBOSE:
    //    for Xi in X[-32:]:
    //    print '%s %s' % (print_hash(Xi[0]), Xi[1])

    X = X.sortBy(_._1.toIterable)

    log.debug("- Finding collisions")

    val solns = ArrayBuffer.empty[Seq[Int]]

    for {i <- 0 until X.size - 1} {
      val res = xor(X(i)._1, X(i+1)._1)
      if (countZeroes(res) == n && distinctIndices(X(i)._2, X(i+1)._2)) {
        val Xi = X(i)
        val Xi1 = X(i+1)
        if (X(i)._2(0) < X(i+1)._2(0)) {
          solns.append(Xi._2.toSeq ++ Xi1._2)
        } else {
          solns.append(Xi1._2.toSeq ++ Xi._2)
        }
      }
    }
    solns
  }

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
