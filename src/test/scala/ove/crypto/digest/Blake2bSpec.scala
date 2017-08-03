package ove.crypto.digest

import org.scalatest.{Matchers, PropSpec}
import org.scalatest.prop.PropertyChecks
import scorex.crypto.encode.Base58

class Blake2bSpec extends PropSpec with PropertyChecks with Matchers {
  property("method clone should works") {
    val digest = Blake2b.Digest.newInstance(new Blake2b.Param().setDigestLength(32).setPersonal(Array.fill(2)(0.toByte)))
    digest.update(Array.fill(5)(1.toByte))
    val d1 = digest.digestWithoutBufferReset()
    val d11 = digest.digestWithoutBufferReset()
    val clone = digest.clone()
    val d2 = clone.digestWithoutBufferReset()
    val d22 = clone.digestWithoutBufferReset()
    all(Seq(d1, d11, d2, d22).map(Base58.encode)) shouldBe "GqMN94aJ31BHyBVwACo3zfqAb25QF17iR9tXqMHpEArX"
  }
}
