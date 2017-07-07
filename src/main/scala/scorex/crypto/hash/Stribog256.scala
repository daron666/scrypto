package scorex.crypto.hash

import java.security.{MessageDigest, Security}

import gost.GOSTProvider

object Stribog256 extends CryptographicHash32 {
  if (Security.getProvider("GOST") == null) Security.addProvider(new GOSTProvider)

  override def hash(input: Array[Byte]): Digest = MessageDigest.getInstance("GOST3411-2012.256").digest(input)
}