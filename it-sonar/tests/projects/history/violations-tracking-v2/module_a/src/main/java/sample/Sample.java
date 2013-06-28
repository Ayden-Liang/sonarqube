package sample;

public class Sample {

	public Sample(int i) {
		int j = i+1; // still the same violation: unused local variable
	}
	
	public boolean avoidUtilityClass() {
		return true;
	}
	
	private String myMethod() { // violation "unused private method" is fixed because it's called in newViolation
		return "hello";
	}

  public void newViolation() {
    String msg = myMethod(); // new violation : msg is an unused variable
  }
}
