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

  def countLeadingZeroes(bytes: Array[Int]): Int = {
    val byteSize = 8
    (0 until byteSize * bytes.size).foldLeft(0) {
      case (res, i) if (bytes(i / byteSize) << i % byteSize & 0x80) == 0 => res + 1
      case (res, _) => return res
    }
  }

  def hasCollision(ha: Array[Int], hb: Array[Int], i: Int, lenght: Int): Boolean = {
    ((i - 1) * lenght / 8 until i * lenght / 8).forall(j => ha(j) == hb(j))
  }

  def distinctIndices(a: Seq[Int], b: Seq[Int]): Boolean = !a.exists(b.contains)

  def xor(ha: Array[Int], hb: Array[Int]): Array[Int] = {
    for {(a, b) <- ha.zip(hb)} yield a ^ b
  }

  private val log = LoggerFactory.getLogger(getClass)

  def expandArray(inp: Array[Byte], outLen: Int, bitLen: Int, bytePad: Int = 0): Array[Int] = {
    val wordSize = 32
    val wordMask = BigInteger.ONE.shiftLeft(wordSize).subtract(BigInteger.ONE)

    assert(bitLen >= 8 && wordSize >= 7 + bitLen)

    val outWidth = (bitLen + 7) / 8 + bytePad
    assert(outLen == 8 * outWidth * inp.length / bitLen)
    val out = new Array[Int](outLen)

    val bitLenMask = BigInteger.valueOf((1 << bitLen) - 1)
    val byteMask = BigInteger.valueOf(0xFF)

    // The acc_bits least - significant bits of acc_value represent a bit sequence in big-endian order.
    var accBits = 0
    var accValue = BigInteger.ZERO

    var j = 0
    for (i <- inp.indices) {
      accValue = accValue.shiftLeft(8).and(wordMask).or(BigInteger.valueOf((inp(i) & 0xFF).toLong))
      accBits += 8

      // When we have bit_len or more bits in the accumulator, write the next output element.
      if (accBits >= bitLen) {
        accBits -= bitLen
        for (x <- bytePad until outWidth)
          out.update(j + x, {
            // Big-endian
            accValue.shiftRight(accBits + (8 * (outWidth - x - 1))).and(
              // Apply bitLenMask across byte boundaries
              bitLenMask.shiftRight(8 * (outWidth - x - 1)).and(byteMask)).intValueExact()
          })

        j += outWidth
      }
    }

    out
  }


  // Implementation of Basic Wagner's algorithm for the GBP
  private[hash] def gbpBasic(digest: Digest, n: Int, k: Int): Seq[Seq[Int]] = {
    val collisionLength = n / (k + 1)
    val hashLength = (k + 1) * ((collisionLength + 7) / 8)
    val indicesPerHashOutput = 512 / n
    log.debug("Generating first list")
    //  1) Generate first list
    var X = ArrayBuffer.empty[(Array[Int], Seq[Int])]
    var tmpHash = Array.empty[Byte]
    for {i <- 0 until Math.pow(2, collisionLength + 1).toInt} {
      val r = i % indicesPerHashOutput
      if (r == 0) {
        //  X_i = H(I||V||x_i)
        val currDigest = digest.clone()
        hashXi(currDigest, i / indicesPerHashOutput)
        tmpHash = currDigest.digest()
      }
      val d = tmpHash.slice(r * n / 8, (r + 1) * n / 8)
      val expanded = expandArray(d, hashLength, collisionLength)
      val p = (expanded, Seq(i))
      X += p
    }

    //  3) Repeat step 2 until 2n/(k+1) bits remain
    for (i <- 1 until k) {
      log.debug(s"Round $i")

      //  2a) Sort the list
      log.debug("- Sorting list")
      X = X.sortBy(_._1.toIterable)

      log.debug("- Finding collisions")
      var Xc = ArrayBuffer.empty[(Array[Int], Seq[Int])]
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

    X = X.sortBy(_._1.toIterable)

    log.debug("- Finding collisions")

    val solns = ArrayBuffer.empty[Seq[Int]]

    while (X.nonEmpty) {
      val XSize = X.length

      // to?
      val j = (1 until XSize).find(j => !(hasCollision(X.last._1, X(XSize - 1 - j)._1, k, collisionLength) &&
        hasCollision(X.last._1, X(XSize - 1 - j)._1, k + 1, collisionLength))).getOrElse(XSize)

      for (l <- 0 until j - 1) {
        for (m <- l + 1 until j) {
          val res = xor(X(XSize - 1 - l)._1, X(XSize - 1 - m)._1)
          if (countLeadingZeroes(res) == 8 * hashLength && distinctIndices(X(XSize - 1 - l)._2, X(XSize - 1 - m)._2)) {
            //        if DEBUG and VERBOSE:
            //          print 'Found solution:'
            //        print '- %s %s' % (print_hash(X[-1-l][0]), X[-1-l][1])
            //        print '- %s %s' % (print_hash(X[-1-m][0]), X[-1-m][1])
            if (X(XSize - 1 - l)._2(0) < X(XSize - 1 - m)._2(0)) {
              solns.append(X(XSize - 1 - l)._2 ++ X(XSize - 1 - m)._2)
            } else {
              solns.append(X(XSize - 1 - m)._2 ++ X(XSize - 1 - l)._2)
            }
          }
        }
      }

      // 2d) Drop this set
      X = X.take(XSize - j)
    }

    solns
  }

  /**
    * Generate n-bit word at specified index.
    *
    * @param n                Word length in bits
    * @param digestWithoutIdx digest without index
    * @param idx              word index
    * @return word
    */
  // https://github.com/str4d/zcash-pow/blob/master/test-pow.py
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
    * https://github.com/jorisvr/equihash-xenon/blob/87c5ec80b0817823ef163ef9802ca514dbfa2313/python/validate.py
    *
    * @param n               Word length in bits
    * @param k               2-log of number of indices per solution
    * @param personal        Personal bytes for digest
    * @param header          Block header with nonce, 140 bytes
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
