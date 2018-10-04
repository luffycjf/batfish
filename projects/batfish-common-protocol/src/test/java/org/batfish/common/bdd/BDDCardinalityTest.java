package org.batfish.common.bdd;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

import java.math.BigInteger;
import net.sf.javabdd.BDD;
import org.batfish.datamodel.Ip;
import org.batfish.datamodel.Prefix;
import org.junit.Test;

public class BDDCardinalityTest {
  private static final BDDPacket PKT = new BDDPacket();
  private static final IpSpaceToBDD TO_BDD = new IpSpaceToBDD(PKT.getFactory(), PKT.getDstIp());
  private static final BigInteger TWO = BigInteger.valueOf(2);

  private static BigInteger cardinality(BDD bdd) {
    return BDDCardinality.cardinality(bdd, 32);
  }

  @Test
  public void testTrivial() {
    assertThat(cardinality(PKT.getFactory().zero()), equalTo(BigInteger.ZERO));
    assertThat(cardinality(PKT.getFactory().one()), equalTo(TWO.pow(32)));
  }

  @Test
  public void testIp() {
    BDD bdd = TO_BDD.toBDD(new Ip("1.1.1.1"));
    assertThat(cardinality(bdd), equalTo(BigInteger.ONE));
  }

  @Test
  public void testOr() {
    BDD bdd = TO_BDD.toBDD(new Ip("1.1.1.1")).or(TO_BDD.toBDD(new Ip("2.2.2.2")));
    assertThat(cardinality(bdd), equalTo(TWO));
  }

  @Test
  public void testPrefix() {
    BDD bdd = TO_BDD.toBDD(Prefix.parse("1.0.0.0/8"));
    assertThat(cardinality(bdd), equalTo(TWO.pow(24)));
  }

  @Test
  public void testDoC() {
    BDD slash8 = TO_BDD.toBDD(Prefix.parse("1.0.0.0/8"));
    BDD slash16 = TO_BDD.toBDD(Prefix.parse("1.0.0.0/16"));
    BDD bdd = slash8.and(slash16.not());
    assertThat(cardinality(bdd), equalTo(TWO.pow(24).subtract(TWO.pow(16))));
  }
}
