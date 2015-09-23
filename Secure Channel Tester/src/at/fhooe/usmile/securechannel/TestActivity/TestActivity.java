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
import at.fhooe.usmile.securechannel.UsmileSecureChannel.KEYAGREEMENT_PROTOCOL;
import at.fhooe.usmile.securechanneltest.R;

/**
 * @author Endalkachew Asnake Application to test the speed of the secure
 *         channel to the Secure Element
 */
public class TestActivity extends Activity implements OnClickListener,
		IChannelStatusListener {

	private final static byte[] APPLETAID_SRP6a = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05,
			0x08, 0x00, 0x01 };
	private final static byte[] APPLETAID_ECSRP = new byte[] { 0x65, 0x63, 0x73, 0x72, 0x70 };
	
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

	private Handler mStatusMsgHandler = new Handler();
	private String mStatusMsg;

	// for testing
	private boolean testThreadRunning = false;

	private long mStartTime = 0L;
	private long mEndTime = 0L;

	private File mExternalDir = Environment.getExternalStorageDirectory();
	private FileWriter mWriterStage1;
	private FileWriter mWriterStage2;
	private FileWriter mWriterComplete;
	private FileWriter mWriterSS;

	private int mTestCounter = 0;
	
	private byte[] mAppletAID;

	private KEYAGREEMENT_PROTOCOL mKeyAgreementProtocol;
	
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

		mAppletAID = APPLETAID_ECSRP;
		mKeyAgreementProtocol = KEYAGREEMENT_PROTOCOL.KEYAGREEMENT_ECSRP;
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
			mTestCounter = 0;
			mStartTime = System.nanoTime();

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
				mWriterStage1 = new FileWriter(new File(mExternalDir,
						new Date().getTime() + "_stage1.txt"));
				mWriterStage2 = new FileWriter(new File(mExternalDir,
						new Date().getTime() + "_stage2.txt"));
				mWriterComplete = new FileWriter(new File(mExternalDir,
						new Date().getTime() + "_complete.txt"));

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
					mWriterSS = new FileWriter(new File(mExternalDir,
							new Date().getTime() + "secureSession48bytes.txt"));
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}

				Thread secureSessionTest = new Thread() {
					@Override
					public void run() {
						byte[] testData = new byte[testDataSize];
						byte[] response;
						CommandApdu cmdApdu;
						
						for (int i = 0; i < maxIteration; i++) {

							SecureRandom r = new SecureRandom();
							r.nextBytes(testData);
							System.out.println("sent random : "
									+ Converter.getHex(testData));
							
							cmdApdu = new CommandApdu((byte) 0x80, (byte) 0x30,
									(byte) 0x00, (byte) 0x00, testData,
									(byte) 0x00);

							mStartTime = System.nanoTime();

							response = usChannel.encodeAndSend(cmdApdu);

							mEndTime = System.nanoTime();

							mStatusMsg = "\nSecure Messaging test " + (i + 1)
									+ " -> " + ((mEndTime - mStartTime) / 1000)
									+ "  usec";

							try {
								mWriterSS.write("\n" + (mEndTime - mStartTime)
										/ 1000);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
							mStatusMsgHandler.post(statusUpdate);
							System.out.println(mStatusMsg);

							System.out.println("+ve response : "
									+ Converter.getHex(response));
						}
						testThreadRunning = false;
						try {
							mWriterSS.close();
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
			statusTextView.append(mStatusMsg);
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

		mTestCounter++;
		statusTextView.append("\n Test number : " + mTestCounter
				+ "\n  Step 1 SE response time >: "
				+ usChannel.getResponseTimeKeyAgreementInit() + " usec"
				+ "\n  Step 2 SE response time >: "
				+ usChannel.getResponseTimeAuthentication() + " usec"
				+ "\n  				Overall Time >: " + usChannel.getOverallTime()
				+ " usec" + "\n=========================================");
		try {
			mWriterStage1.write("\n"
					+ String.valueOf(usChannel
							.getResponseTimeKeyAgreementInit()));
			mWriterStage2
					.write("\n"
							+ String.valueOf(usChannel
									.getResponseTimeAuthentication()));
			mWriterComplete.write("\n"
					+ String.valueOf(usChannel.getOverallTime()));

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		synchronized (this) {
			scrollView.fullScroll(ScrollView.FOCUS_DOWN);
		}

		if (mTestCounter < maxIteration) {
			usChannel.closeSession();
			usChannel = new UsmileSecureChannel(getApplicationContext(), this);
		} else {
			mTestCounter = 0;

			testThreadRunning = false;
			try {
				mWriterStage1.close();
				mWriterStage2.close();
				mWriterComplete.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	@Override
	public void serviceAvailable(String[] terminals) {
		if (spinnerReader.getCount() == 0) {
			ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
					android.R.layout.simple_spinner_dropdown_item, terminals);
			// Specify the layout to use when the list of choices appears
			adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
			// Apply the adapter to the spinner
			spinnerReader.setAdapter(adapter);
		}
		
		if (testThreadRunning) {
			usChannel.initConnection(mAppletAID, readerIndex, mKeyAgreementProtocol);
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
