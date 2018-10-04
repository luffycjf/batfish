package org.batfish.common.bdd;

import java.math.BigInteger;
import java.util.stream.Stream;
import net.sf.javabdd.BDD;

public class BDDCardinality {

  public static BigInteger cardinality(BDD bdd) {
    return cardinality(bdd, bdd.getFactory().varNum());
  }

  public static BigInteger cardinality(BDD bdd, int vars) {
    return implicants(bdd)
        .map(path -> implicantCardinality(path, vars))
        .reduce(BigInteger.ZERO, BigInteger::add);
  }

  private static BigInteger implicantCardinality(BDD implicant, int vars) {
    return BigInteger.valueOf(2).pow(vars - implicantLength(implicant));
  }

  private static int implicantLength(BDD implicant) {
    if (implicant.isOne()) {
      return 0;
    }
    return implicant.high().isZero()
        ? implicantLength(implicant.low()) + 1
        : implicantLength(implicant.high()) + 1;
  }

  public static Stream<BDD> implicants(BDD bdd) {
    if (bdd.isZero()) {
      return Stream.of();
    }
    if (bdd.isOne()) {
      return Stream.of(bdd);
    }
    BDD var = bdd.getFactory().ithVar(bdd.var());
    BDD notVar = var.not();
    return Stream.concat(
        implicants(bdd.high()).map(var::and), implicants(bdd.low()).map(notVar::and));
  }
}
