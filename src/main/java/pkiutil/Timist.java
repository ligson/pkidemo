package pkiutil;

public class Timist {
	private long costTime = 0;
	private long startTime = -1;
	// private long pauseTime = -1;
	private boolean isPause = false;

	public void start() {
		if (!isPause && startTime == -1) startTime = System.currentTimeMillis();
		else throw new RuntimeException("Timist is busy.");
	}

	public long stop() {
		if (isPause) {
			return costTime;
		} else if (startTime != -1) {
			costTime += System.currentTimeMillis() - startTime;
			return costTime;
		} else {
			throw new RuntimeException("Timist is not start.");
		}
	}

	public boolean pauseSwitch() {
		if (!isPause) {
			costTime += System.currentTimeMillis() - startTime;
			startTime = -1;
			isPause = true;
		} else {
			startTime = System.currentTimeMillis();
			isPause = false;
		}
		return isPause;
	}

	public void reset() {
		costTime = 0;
		startTime = -1;
		// pauseTime = -1;
		isPause = false;
	}
}