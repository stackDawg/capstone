# Secure Traffic Anomaly Detection System Architecture

## Current Architecture

```
                                   +------------------+
                                   |                  |
                                   | ML Model (LSTM)  |
                                   |                  |
                                   +--------^---------+
                                            |
                                            | Loads
                                            |
+------------------+  OpenFlow  +----------------------+  Feature    +-----------------+
|                  |  Protocol  |                      | Extraction  |                 |
|  Mininet Network |<---------->|  Ryu SDN Controller  |<----------->| Flow Classifier |
|                  |            |                      |             |                 |
+------------------+            +----------------------+             +-----------------+
    |        |                           |
    |        |                           | Flow Removal
    |        |                           v
+---v---+ +--v----+                +-----------+
|       | |        |               |           |
| Host1 | | Host2  |               | Anomaly   |
|       | |        |               | Log       |
+-------+ +--------+               |           |
                                   +-----------+
```

### Current System Components:

1. **Mininet Network Simulation**
   - Provides virtual network infrastructure
   - Implements test topology with multiple hosts and switches
   - Simulates normal and attack traffic (DDoS using hping3)
   - Connects to the SDN controller via OpenFlow 1.3

2. **Ryu SDN Controller**
   - Manages the network infrastructure
   - Collects flow statistics from switches
   - Invokes the Flow Classifier for anomaly detection
   - Implements basic mitigation by removing detected anomalous flows

3. **Flow Classifier**
   - Loads pre-trained LSTM model
   - Extracts features from network flows
   - Classifies traffic as normal or anomalous
   - Logs detected anomalies

4. **Machine Learning Model**
   - LSTM-based neural network model
   - Trained on CICIDS2017 dataset and live Mininet data
   - Provides binary classification (normal/anomalous)

5. **Anomaly Logging**
   - Records detected anomalies with timestamps
   - Stores flow information (IP, ports, protocol)
   - Maintains statistics for evaluation

### Current Workflow:

1. The Ryu controller connects to switches in the Mininet environment
2. Controller periodically requests flow statistics from the switches
3. Flow data is processed and features are extracted
4. ML model classifies flows as normal or anomalous
5. When anomalies are detected, the controller removes the flow from the switch's flow table
6. Actions and detected anomalies are logged for analysis

## Future Architecture

```
                                       +-----------------+
                                       |                 |
                                       | Multiple ML     |
                                       | Models/Ensemble |
                                       |                 |
                                       +--------^--------+
                                                |
                                                |
+--------------------+                 +--------v---------+           +-------------------+
|                    |                 |                  |           |                   |
| Network Monitoring |---------------->| Feature Pipeline |<--------->| Model Training    |
| Dashboard          |<----------------|                  |           | Pipeline          |
|                    |   Visualization +------------------+           |                   |
+--------------------+                        |                       +-------------------+
                                              |
                                              v
                                    +--------------------+
                                    |                    |
            +------------------+    | Advanced Mitigation|    +--------------------+
            |                  |    | Module             |    |                    |
+--------+  | Network Traffic  |    |                    |    | Security Analytics |
|        |  | Analysis Module  |    | - Rate Limiting    |    | Module             |
| Mininet|  |                  |    | - Quarantine       |    |                    |
| Network|<-|                  |<-->| - Traffic Shaping  |<-->| - Behavior Analysis|
|        |  | - Deep Packet    |    | - Dynamic Rules    |    | - Threat Intel     |
+--------+  |   Inspection     |    | - Load Balancing   |    | - Alert Correlation|
            |                  |    |                    |    |                    |
            +------------------+    +--------------------+    +--------------------+
                   ^                         ^
                   |                         |
                   v                         v
            +------------------------------------------+
            |                                          |
            | Enhanced SDN Controller                  |
            |                                          |
            | - Northbound API                         |
            | - Multi-Controller Support               |
            | - Distributed Detection/Mitigation       |
            | - Intent-Based Networking                |
            |                                          |
            +------------------------------------------+
```

### Future System Components:

1. **Enhanced SDN Controller**
   - Multi-controller support for scalability
   - Comprehensive northbound API for application integration
   - Distributed detection and mitigation capabilities
   - Intent-based networking for policy enforcement

2. **Advanced Mitigation Module**
   - Multiple mitigation strategies beyond flow removal:
     - Rate limiting for suspicious traffic
     - Host quarantine mechanisms
     - Traffic shaping and engineering
     - Dynamic rule generation
     - Load balancing under attack conditions

3. **Network Traffic Analysis Module**
   - Deep packet inspection for encrypted traffic
   - Protocol anomaly detection
   - Session tracking and analysis
   - Real-time feature extraction

4. **Security Analytics Module**
   - Behavioral analysis for network entities
   - Threat intelligence integration
   - Alert correlation and prioritization
   - Automated root cause analysis

5. **Network Monitoring Dashboard**
   - Real-time visualization of network state
   - Interactive topology view
   - Threat detection and mitigation status
   - Historical data analysis and reporting

6. **Feature Pipeline**
   - Enhanced feature engineering
   - Online feature selection
   - Dimensionality reduction
   - Feature standardization

7. **Multiple ML Models/Ensemble**
   - Specialized models for different attack types
   - Ensemble methods for improved accuracy
   - Online learning capabilities
   - Explainable AI components

8. **Model Training Pipeline**
   - Continuous model training and updating
   - Auto ML for hyperparameter optimization
   - Model versioning and comparison
   - Performance metrics tracking

### Future Workflow:

1. Network traffic is continuously monitored across the Mininet environment
2. The enhanced feature pipeline extracts and processes features in real-time
3. Multiple ML models analyze traffic from different perspectives
4. The advanced mitigation module selects appropriate mitigation strategies based on:
   - Attack type and severity
   - Network conditions
   - Historical effectiveness
5. Security analytics module correlates events and provides contextual information
6. Dashboard provides real-time visibility and control to administrators
7. Model training pipeline continuously updates models based on new data

## Implementation Roadmap

1. **Phase 1: Enhanced Mitigation**
   - Implement rate limiting and traffic shaping
   - Develop host quarantine mechanisms
   - Create dynamic rule generation

2. **Phase 2: Improved Monitoring**
   - Develop basic dashboard for network visibility
   - Implement more detailed logging
   - Create traffic visualization tools

3. **Phase 3: Advanced Analytics**
   - Implement security analytics module
   - Integrate behavioral analysis
   - Develop alert correlation mechanisms

4. **Phase 4: Full System Integration**
   - Deploy enhanced controller with distributed capabilities
   - Implement complete model training pipeline
   - Integrate all components into cohesive system 