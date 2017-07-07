package scorex.crypto.hash

import java.security.{MessageDigest, Security}

import gost.GOSTProvider

object Stribog512 extends CryptographicHash64 {
  if (Security.getProvider("GOST") == null) Security.addProvider(new GOSTProvider)

  override def hash(input: Array[Byte]): Digest = MessageDigest.getInstance("GOST3411-2012.512").digest(input)
}