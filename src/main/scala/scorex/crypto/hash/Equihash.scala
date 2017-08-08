package scorex.crypto.hash

import java.math.BigInteger

import org.slf4j.LoggerFactory
import ove.crypto.digest.Blake2b
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

  def countLeadingZeroes(bytes: Array[Byte]): Int = {
    val byteSize = 8
    (0 until byteSize * bytes.size).foldLeft(0) {
      case (res, i) if (bytes(i / byteSize) << i % byteSize & 0x80) == 0 => res + 1
      case (res, _) => return res
    }
  }

  def hasCollision(ha: Array[Byte], hb: Array[Byte], i: Int, lenght: Int): Boolean = {
    ((i - 1) * lenght / 8 until i * lenght / 8).forall(j => ha(j) == hb(j))
  }

  def distinctIndices(a: Seq[Int], b: Seq[Int]): Boolean = !a.exists(b.contains)

  def xor(ha: Array[Byte], hb: Array[Byte]): Array[Byte] = {
    for {(a, b) <- ha.zip(hb)} yield (a ^ b).toByte
  }

  private val log = LoggerFactory.getLogger(getClass)

  // Implementation of Basic Wagner's algorithm for the GBP
  private[hash] def gbpBasic(digest: Digest, n: Int, k: Int): Seq[Seq[Int]] = {
    val collisionLength = n / (k + 1)
    log.debug("Generating first list")
    //  1) Generate first list
    var X = ArrayBuffer.empty[(Array[Byte], Seq[Int])]
    for {i <- 0 until Math.pow(2, collisionLength + 1).toInt} {
      //  X_i = H(I||V||x_i)
      val currDigest = digest.clone()
      hashXi(currDigest, i)
      val d = currDigest.digest()
      val p = (d, Seq(i))
      X += p
    }

    //  3) Repeat step 2 until 2n/(k+1) bits remain
    for (i <- 1 until k) {
      log.debug(s"Round $i")

      //  2a) Sort the list
      log.debug("- Sorting list")
      X = X.sortBy(_._1.map(_ & 0xFF).toIterable)

      log.debug("- Finding collisions")
      var Xc = ArrayBuffer.empty[(Array[Byte], Seq[Int])]
      while (X.nonEmpty) {
        //  2b) Find next set of unordered pairs with collisions on first n/(k+1) bits
        val XSize = X.size
        val j = (1 until XSize).find(j => !hasCollision(X.last._1, X(XSize - 1 - j)._1, i, collisionLength)).getOrElse(XSize)

        //  2c) Store tuples (X_i ^ X_j, (i, j)) on the table
        for {
          l <- 0 until j - 1
          m <- l + 1 until j
        } {
          val X1l = X(XSize - 1 - l)
          val X1m = X(XSize - 1 - m)
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

        //  2d) Drop this set
        X = X.take(XSize - j)
      }
      //  2e) Replace previous list with new list
      X = Xc
    }

    //  k+1) Find a collision on last 2n(k+1) bits
    log.debug("Final round:")
    log.debug("- Sorting list")

    X = X.sortBy(_._1.map(_ & 0xFF).toIterable)

    log.debug("- Finding collisions")

    val solns = ArrayBuffer.empty[Seq[Int]]

    for {i <- 0 until X.size - 1} {
      val xorResult = xor(X(i)._1, X(i + 1)._1)
      if (countLeadingZeroes(xorResult) == n && distinctIndices(X(i)._2, X(i + 1)._2)) {
        val Xi = X(i)
        val Xi1 = X(i + 1)
        if (X(i)._2(0) < X(i + 1)._2(0)) {
          solns.append(Xi._2 ++ Xi1._2)
        } else {
          solns.append(Xi1._2 ++ Xi._2)
        }
      }
    }
    solns
  }

  /**
    * Generate n-bit word at specified index.
    * @param n Word length in bits
    * @param digestWithoutIdx digest without index
    * @param idx word index
    * @return word
    */
  def generateWord(n: Int, digestWithoutIdx: Digest, idx: Int): BigInteger = {
    val bytesPerWord = n / 8
    val wordsPerHash = 512 / n

    val hidx = idx / wordsPerHash
    val hrem = idx % wordsPerHash

    val idxdata = leIntToByteArray(hidx)
    val ctx1 = digestWithoutIdx.clone()
    ctx1.update(idxdata)
    val digest = ctx1.digest()

    (hrem * bytesPerWord until hrem * bytesPerWord + bytesPerWord).foldLeft(BigInteger.ZERO) {
      case (w, i) => w.shiftLeft(8).or(BigInteger.valueOf((digest(i) & 0xFF).toLong))
    }
  }

  /**
    * Validate an Equihash solution.
    * @param n Word length in bits
    * @param k 2-log of number of indices per solution
    * @param personal Personal bytes for digest
    * @param header Block header with nonce, 140 bytes
    * @param solutionIndices Solution indices
    * @return Return True if solution is valid, False if not.
    */
  def validateSolution(n: Int, k: Int, personal: Array[Byte], header: Array[Byte], solutionIndices: Seq[Int]): Boolean = {
    assert(n > 1)
    assert(k >= 3)
    assert(n % 8 == 0)
    assert(n % (k + 1) == 0)

    val solutionLen = Math.pow(2, k).toInt
    assert(solutionIndices.size == solutionLen)

    // Check for duplicate indices.
    if (solutionIndices.toSet.size != solutionIndices.size) {
      false
    } else {
      // Generate hash words.
      val bytesPerWord = n / 8
      val wordsPerHash = 512 / n
      val outlen = wordsPerHash * bytesPerWord

      val digest = Blake2b.Digest.newInstance(new Blake2b.Param().setDigestLength(outlen).setPersonal(personal))
      digest.update(header)

      val words = ArrayBuffer.empty[BigInteger]
      for (i <- 0 until solutionLen) {
        words += generateWord(n, digest, solutionIndices(i))
      }

      // Check pair-wise ordening of indices.
      for (s <- 0 until k) {
        val d = 1 << s
        for (i <- 0 until solutionLen by 2 * d) {
          if (solutionIndices(i) >= solutionIndices(i + d))
            return false
        }
      }

      // Check XOR conditions.
      val bitsPerStage = n / (k + 1)
      for (s <- 0 until k) {
        val d = 1 << s
        for (i <- 0 until solutionLen by 2 * d) {
          val w = words(i).xor(words(i + d))
          if (w.shiftRight(n - (s + 1) * bitsPerStage) != BigInteger.ZERO)
            return false
          words(i) = w
        }
      }

      // Check final sum zero.
      words(0) == BigInteger.ZERO
    }
  }
}
