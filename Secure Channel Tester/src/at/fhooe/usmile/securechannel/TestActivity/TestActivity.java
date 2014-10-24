package at.fhooe.usmile.securechannel.TestActivity;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;

import android.app.Activity;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.view.Menu;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;
import at.fhooe.usmile.securechannel.CommandApdu;
import at.fhooe.usmile.securechannel.Converter;
import at.fhooe.usmile.securechannel.IChannelStatusListener;
import at.fhooe.usmile.securechannel.UsmileSecureChannel;
import at.fhooe.usmile.securechanneltest.R;

/**
 * @author Endalkachew Asnake Application to test the speed of the secure
 *         channel to the Secure Element
 */
public class TestActivity extends Activity implements OnClickListener,
		IChannelStatusListener {

	final static byte[] appletAID = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05,
			0x08, 0x00, 0x01 };
	private int maxIteration = 3;
	private int testDataSize = 100;
	private int readerIndex = 0;
	private byte[] passwordBytes = "usmile".getBytes();
	private byte[] userID = "usmile".getBytes();

	private Spinner spinnerDatalen;
	private Spinner spinnerIteration;
	private Spinner spinnerReader;
	private Button btnTestKeyAg;
	private Button btnTestSecSession;
	private UsmileSecureChannel usChannel;
	private TextView statusTextView;
	private ScrollView scrollView;

	private Handler statusMsgHandler = new Handler();
	private String statusMsg;

	// for testing
	private boolean testThreadRunning = false;

	private long startTime = 0L;
	private long endTime = 0L;

	private File dir = Environment.getExternalStorageDirectory();
	private FileWriter writerStage1;
	private FileWriter writerStage2;
	private FileWriter writerComplete;
	private FileWriter writerSS;
	private CommandApdu cmdApdu;

	private int testCount = 0;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		btnTestKeyAg = (Button) findViewById(R.id.btnTest);
		btnTestSecSession = (Button) findViewById(R.id.btnTestSecureSession);
		statusTextView = (TextView) findViewById(R.id.statusTextView);

		spinnerDatalen = (Spinner) findViewById(R.id.spinnerDataLen);
		spinnerIteration = (Spinner) findViewById(R.id.spinnerIteration);
		spinnerReader = (Spinner) findViewById(R.id.spinnerReaderList);
		btnTestKeyAg.setOnClickListener(this);
		btnTestSecSession.setOnClickListener(this);
		scrollView = (ScrollView) findViewById(R.id.scrollViewSDCard);

		if (usChannel != null) {
			usChannel.closeSession();
		}
		usChannel = new UsmileSecureChannel(getApplicationContext(), this);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
		return true;
	}

	@Override
	public void onClick(View v) {
		// TODO Auto-generated method stub
		if (testThreadRunning) {
			return;
		}
		if (v.getId() == R.id.btnTest && spinnerReader.getCount() > 0) {

			testThreadRunning = true;
			testCount = 0;
			startTime = System.nanoTime();

			readerIndex = spinnerReader.getSelectedItemPosition();
			maxIteration = Integer.parseInt(spinnerIteration.getSelectedItem()
					.toString());
			testDataSize = Integer.parseInt(spinnerDatalen.getSelectedItem()
					.toString());

			if (usChannel != null) {
				usChannel.closeSession();
			}
			usChannel = new UsmileSecureChannel(getApplicationContext(), this);
			try {
				writerStage1 = new FileWriter(new File(dir,
						new Date().toString() + "stage1.txt"));
				writerStage2 = new FileWriter(new File(dir,
						new Date().toString() + "stage2.txt"));
				writerComplete = new FileWriter(new File(dir,
						new Date().toString() + "complete.txt"));

			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} else if (v.getId() == R.id.btnTestSecureSession) {
			if (usChannel.isSessionSecure()) {
				testThreadRunning = true;
				maxIteration = Integer.parseInt(spinnerIteration
						.getSelectedItem().toString());
				testDataSize = Integer.parseInt(spinnerDatalen
						.getSelectedItem().toString());
				try {
					writerSS = new FileWriter(new File(dir,
							new Date().toString() + "secureSession48bytes.txt"));
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				Thread secureSessionTest = new Thread() {
					@Override
					public void run() {
						// TODO Auto-generated method stub

						byte[] testData = new byte[testDataSize];

						byte[] response;

						for (int i = 0; i < maxIteration; i++) {

							SecureRandom r = new SecureRandom();
							r.nextBytes(testData);
							System.out.println("sent random : "
									+ Converter.getHex(testData));
							cmdApdu = new CommandApdu((byte) 0x80, (byte) 0x30,
									(byte) 0x00, (byte) 0x00, testData,
									(byte) 0x00);

							startTime = System.nanoTime();

							response = usChannel.encodeAndSend(cmdApdu);

							endTime = System.nanoTime();

							statusMsg = "\nSecure Messaging test " + (i + 1)
									+ " -> " + ((endTime - startTime) / 1000)
									+ "  usec";

							try {
								writerSS.write("\n" + (endTime - startTime)
										/ 1000);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
							statusMsgHandler.post(statusUpdate);
							System.out.println(statusMsg);

							System.out.println("+ve response : "
									+ Converter.getHex(response));
						}
						testThreadRunning = false;
						try {
							writerSS.close();
						} catch (IOException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
				};
				secureSessionTest.start();

			}

		}
	}

	private Runnable statusUpdate = new Runnable() {

		@Override
		public void run() {
			// TODO Auto-generated method stub
			statusTextView.append(statusMsg);
			scrollView.post(new Runnable() {
				public void run() {
					synchronized (this) {
						scrollView.fullScroll(ScrollView.FOCUS_DOWN);
					}
				}
			});
		}
	};

	@Override
	public void scAuthenticated() {

		testCount++;
		statusTextView.append("\n Test number : " + testCount
				+ "\n  Step 1 SE response time >: "
				+ usChannel.getResponseTimeKeyAgreementInit() + " usec"
				+ "\n  Step 2 SE response time >: "
				+ usChannel.getResponseTimeAuthentication() + " usec"
				+ "\n  				Overall Time >: " + usChannel.getOverallTime()
				+ " usec" + "\n=========================================");
		try {
			writerStage1.write("\n"
					+ String.valueOf(usChannel
							.getResponseTimeKeyAgreementInit()));
			writerStage2
					.write("\n"
							+ String.valueOf(usChannel
									.getResponseTimeAuthentication()));
			writerComplete.write("\n"
					+ String.valueOf(usChannel.getOverallTime()));

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		synchronized (this) {
			scrollView.fullScroll(ScrollView.FOCUS_DOWN);
		}

		if (testCount < maxIteration) {
			usChannel.closeSession();
			usChannel = new UsmileSecureChannel(getApplicationContext(), this);
			// usChannel.establishSecureSession(passwordBytes);
		} else {
			testCount = 0;

			testThreadRunning = false;
			try {
				writerStage1.close();
				writerStage2.close();
				writerComplete.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

	}

	@Override
	public void serviceAvailable(String[] terminals) {
		// TODO Auto-generated method stub
		if (spinnerReader.getCount() == 0) {
			ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
					android.R.layout.simple_spinner_dropdown_item, terminals);
			// Specify the layout to use when the list of choices appears
			adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
			// Apply the adapter to the spinner
			spinnerReader.setAdapter(adapter);
		}
		if (testThreadRunning) {
			usChannel.initConnection(appletAID, readerIndex);
		}

	}

	@Override
	public void scInitialized() {
		// TODO Auto-generated method stub
		usChannel.authenticate(userID, passwordBytes);

	}

	@Override
	public void scFailed(String reason) {

		statusTextView.append("\nConnection failed : " + reason);
		testThreadRunning = false;
	}

	@Override
	public void scBlocked() {
		// TODO Auto-generated method stub
		Toast.makeText(getApplicationContext(), "channel blocked",
				Toast.LENGTH_LONG).show();
	}

	@Override
	public void scTerminated() {
		// TODO Auto-generated method stub

	}

	@Override
	public void scPasswordChanged() {
		// TODO Auto-generated method stub

	}
}
