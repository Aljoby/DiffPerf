#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <sched.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <math.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <unistd.h>
#include <bfsys/bf_sal/bf_sys_intf.h>
#include <bf_types/bf_types.h>
#include <dvm/bf_drv_intf.h>
#include <lld/lld_reg_if.h>
#include <lld/lld_err.h>
//#include <lld/bf_ts_if.h>
#include <knet_mgr/bf_knet_if.h>
#include <knet_mgr/bf_knet_ioctl.h>
#include <pkt_mgr/pkt_mgr_intf.h>
#include <tofino/pdfixed/pd_common.h>
#include <pcap.h>
#include <arpa/inet.h>
//#include <tofinopd/diffperf/pd/pd.h>
#include <tofino/pdfixed/pd_common.h>
#include <tofino/pdfixed/pd_conn_mgr.h>
#include <port_mgr/bf_port_if.h>
#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.hpp>
#include <bf_rt/bf_rt_table_data.hpp>
#include <bf_rt/bf_rt_table.hpp>
#include <bf_rt/bf_rt_session.hpp>

#ifdef __cplusplus
// if we are being compiled with a C++ compiler then declare the
// following functions as C functions to prevent name mangling.
//extern "C" is meant to be recognized by a C++ compiler and to notify the compiler that the noted function is (or to be) compiled in C style.
//Take an example, if you are working on a C++ project but it also deals with some existing C functions/libraries.
//You want to wrap them in a C++ module or compile them with other C++ objects without any C++ compiler errors, then you would declare the C function prototypes in an extern "C" block to notify the compiler that they would be compiled along with other C++ functions into one module.
extern "C" {
#endif
#include <bf_switchd/bf_switchd.h>
#include <traffic_mgr/traffic_mgr_sch_intf.h>
#include <traffic_mgr/traffic_mgr_q_intf.h>
#include <traffic_mgr/traffic_mgr_pool_intf.h>
#include <traffic_mgr/traffic_mgr_types.h>
#include <lld/bf_ts_if.h>
#ifdef __cplusplus
}
#endif

#ifndef SDE_INSTALL
#error "Please add -DSDE_INSTALL=\"$SDE_INSTALL\" to CPPFLAGS"
#endif

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

// typedef int bool
#define true 1
#define false 0
#define THRIFT_PORT_NUM 7777
#define MAKE_288_PORT(pipe, l_port) (72 * pipe + l_port)
#define DEV_PORT_TO_PIPE(x) (((x) >> 7) & 3)
#define DEV_PORT_TO_LOCAL_PORT(x) ((x)&0x7F)
#define TOFINO_DEV_ID 0
#define ALL_PIPES 0xffff // new
#define BCAST_GRP 1
#define MAX_ACTIVE_FLOWS 100
#define FLOW_REG_SIZE (MAX_ACTIVE_FLOWS + 1)
#define NUM_PIPES 2   // 2 pipes on our Wedge100BF-32X
#define DIFFPERF_EGRESS_PORT 168
#define DIFFPERF_REVERSE_EGRESS_PORT 184
#define MAX_QUEUES_PER_PORT 8
#define TEST_QUEUE_ID 0
#define PORT_RATE_LIMIT_SPEED_KBPS 120000  // 120 Mbps
#define LINK_UP 1
#define LINK_DOWN 0

#define TCP_ALONE_STR "tcp_alone"

#define QUEUE_BUFFER_SIZE_500_KB 6250 // 6250 x 80bytes = 500KB
#define QUEUE_BUFFER_SIZE_1_MB 12500 // 12500 x 80bytes = 1MB
#define QUEUE_BUFFER_SIZE_5_MB 62500 // 62500 x 80bytes = 5MB
#define QUEUE_BUFFER_SIZE_10_MB 125000 // 125000 x 80bytes = 10MB
#define APP_POOL_0_SIZE 262500 // 21MB
#define DEFAULT_APP_POOL 0
#define LONG_RTT_QUEUE_ID 0
#define SHORT_RTT_QUEUE_ID 1

#define DIFFPERF_SHALLOW_QUEUE_SIZE QUEUE_BUFFER_SIZE_1_MB
#define DIFFPERF_DEEP_QUEUE_SIZE QUEUE_BUFFER_SIZE_10_MB

#define DIFFPERF_CURR_QUEUE_SIZE DIFFPERF_DEEP_QUEUE_SIZE

/*  CUSTOM STRUCTS  */
struct flowInfo{
  int flowId;
  char srcIPAddr[16];
  char destIPAddr[16];
  double flowThr;
  int flowQueue;
};

/* GLOBAL VARIABLES */
int topology_port_list[5] = {136, 168, 128, 129, 184};

bf_rt_target_t dev_tgt; // new

p4_pd_sess_hdl_t sess_hdl;
int switchid = 0;
p4_pd_dev_target_t p4_dev_tgt = {0, (uint16_t)PD_DEV_PIPE_ALL};
//p4_pd_status_t status;
bf_status_t status;
//int array_size = FLOW_REG_SIZE * NUM_PIPES;
int array_size = FLOW_REG_SIZE;
//uint32_t prev_flow_bytes[FLOW_REG_SIZE * NUM_PIPES], curr_flow_bytes[FLOW_REG_SIZE * NUM_PIPES];
uint32_t prev_flow_bytes[FLOW_REG_SIZE], curr_flow_bytes[FLOW_REG_SIZE];
// double throughput_values_from_dp[FLOW_REG_SIZE];  // dp = data-plane
struct timeval prev_time, curr_time;
bool first_bytes_read=true;


// Session object
std::shared_ptr<bfrt::BfRtSession> session;

// BfRt-Info: All information about all the objects available to the control plane
const bfrt::BfRtInfo *bfrtInfo = nullptr;
auto hwflag = bfrt::BfRtTable::BfRtTableGetFlag::GET_FROM_HW;

// Registers flow_bytes
const bfrt::BfRtTable *reg_flow_bytes = nullptr;
bf_rt_id_t reg_flow_bytes_index;
bf_rt_id_t reg_flow_bytes_f1;
std::unique_ptr<bfrt::BfRtTableKey> reg_flow_bytes_key;
std::unique_ptr<bfrt::BfRtTableData> reg_flow_bytes_data;

// Queue diffPerf_set_queue
const bfrt::BfRtTable *diffPerf_set_queue = nullptr;
bf_rt_id_t diffPerf_set_queue_src_addr;
bf_rt_id_t diffPerf_set_queue_dst_addr;
bf_rt_id_t diffPerf_set_queue_set_queue_id;
bf_rt_id_t diffPerf_set_queue_q_id;
std::unique_ptr<bfrt::BfRtTableKey> diffPerf_set_queue_key;
std::unique_ptr<bfrt::BfRtTableData> diffPerf_set_queue_data;

FILE *fp;
struct flowInfo arr[FLOW_REG_SIZE]; 
bool TCP = false;
double BW = PORT_RATE_LIMIT_SPEED_KBPS;
double beta = 0.25;
double Gamma = 0;
int currentIndexShrRTT, currentIndexLngRTT;
int* longRTT; 
int* shortRTT;  
double longRTTBW = 0.0;
double shortRTTBW = 0.0;

// to convert IP address to hexa
int ip_srcAdd;
int ip_dstAdd;
char str_src[16];
char str_dst[16];

struct ip_addr {
    uint32_t   addr;   /* address in network byte order */
    } IP_Address;


void interruptHandler(int dummy) {
  // do all the clean-up
  printf("Inside interruptHandler(). Cleaning up now...\n");
  /* Clean up diffPerf */
  fflush(fp);
  fclose(fp);
  
  if(longRTT != NULL)
    free(longRTT);

  if(shortRTT != NULL)
    free(shortRTT);

  /* Close the Tofino app: closing a session object */
  //status = bfrt::BfRtSession::sessionDestroy(session);
  ///p4_pd_client_cleanup(sess_hdl);
  //printf("INFO: Closed driver session %d\n", session);
  // return BF_SUCCESS;
}

void init_bf_switchd(const char* progname) {
  bf_switchd_context_t *switchd_main_ctx = NULL;
  char *install_dir;
  char target_conf_file[100];

  bf_status_t bf_status;
  install_dir = getenv("SDE_INSTALL");
  sprintf(target_conf_file, "%s/share/p4/targets/tofino/%s.conf", install_dir, progname);

  /* Allocate memory to hold switchd configuration and state */
  if ((switchd_main_ctx = (bf_switchd_context_t *)calloc(1, sizeof(bf_switchd_context_t))) == NULL) {
    printf("ERROR: Failed to allocate memory for switchd context\n");
    return;
  }

  memset(switchd_main_ctx, 0, sizeof(bf_switchd_context_t)); // initialize switchd_main_ctx to 0s
  switchd_main_ctx->install_dir = install_dir; //directory of SDE install
  switchd_main_ctx->conf_file = target_conf_file; // directory of p4Program.conf
  switchd_main_ctx->skip_p4 = false;
  switchd_main_ctx->skip_port_add = false;
  switchd_main_ctx->running_in_background = true;
  switchd_main_ctx->dev_sts_port = THRIFT_PORT_NUM;
  switchd_main_ctx->dev_sts_thread = true;

    /* Initialize the device */
    bf_status = bf_switchd_lib_init(switchd_main_ctx);
    printf("Initialized bf_switchd, status = %d\n", bf_status);
	if (bf_status == 0) {
		printf("Successfully performed client initialization.\n");
	} else {
		///printf("Failed in Client init\n");
        printf("ERROR: Device initialization failed: %s\n", bf_err_str(bf_status));
        exit(1);
	}
}

void getSwitchName () {
  char switchName[25];
  FILE *f = fopen("/etc/hostname","r");
  fscanf(f, "%s", switchName);
  if (strcmp(switchName, "tofino1a") == 0) {
    switchid = 1;
  } else if (strcmp(switchName, "tofino1b") == 0) {
    switchid = 2;
  }
  printf("Detected running on Tofino%d\n", switchid);

  fclose(f);
}

void init_tables() {
  if (switchid == 1) {
    //system("$SDE_INSTALL/bin/bfshell -f ../commands/commands-newtopo-ports-tofino1.txt");
    system("$SDE_INSTALL/bin/bfshell -b ../commands-newtopo-tables-tofino1.py");
    printf("DONE adding commands for initializing tables, ports, and multicast!\n\n\n");
  } 
}


void wait_for_port_link_up(){
  int i, port_state;
  int num_ports = sizeof(topology_port_list)/sizeof(topology_port_list[0]);
  bool all_ports_up = false;

  printf("Number of ports in the topology: %d\n", num_ports);

  printf("Waiting for all ports to be UP... ");
  fflush(stdout);

  while(all_ports_up == false){

    for(i = 0; i < num_ports; i++){
      status = bf_port_oper_state_get(TOFINO_DEV_ID, topology_port_list[i], &port_state);
      if(port_state == LINK_DOWN){
        all_ports_up = false;
        break;
      }
      else if(port_state == LINK_UP){
        all_ports_up = true;
      }
    } // end of for loop
  sleep(1);
  } // end of while loop

  printf(GRN "DONE\n" RESET);
  fflush(stdout);
}

void init_broadcast(void) {

    system("$SDE_INSTALL/bin/bfshell -b ../commands/multicast.py");
}

void print_bf_status(bf_status_t status){
  if(status == BF_SUCCESS){
    printf(GRN "DONE\n" RESET);
  }
  else{
    printf(RED "ERROR: %s\n" RESET, bf_err_str(status));
  }
}

void enable_port_and_queue_rate_limiting(){
  int i;

  printf("Setting rate limit on port %d to %d kbps... ", DIFFPERF_EGRESS_PORT, PORT_RATE_LIMIT_SPEED_KBPS);
  status = bf_tm_sched_port_shaping_rate_set(0, DIFFPERF_EGRESS_PORT, false, 4500, PORT_RATE_LIMIT_SPEED_KBPS);
  print_bf_status(status);

  printf("Enabling rate limiting on port %d... ",DIFFPERF_EGRESS_PORT);
  status = bf_tm_sched_port_shaping_enable(0, DIFFPERF_EGRESS_PORT);
  print_bf_status(status);

  printf("Setting rate limit on port %d to %d kbps... ", DIFFPERF_REVERSE_EGRESS_PORT, PORT_RATE_LIMIT_SPEED_KBPS);
  status = bf_tm_sched_port_shaping_rate_set(0, DIFFPERF_REVERSE_EGRESS_PORT, false, 4500, PORT_RATE_LIMIT_SPEED_KBPS);
  print_bf_status(status);

  printf("Enabling rate limiting on port %d... ",DIFFPERF_REVERSE_EGRESS_PORT);
  status = bf_tm_sched_port_shaping_enable(0, DIFFPERF_REVERSE_EGRESS_PORT);
  print_bf_status(status);

  printf("\n");

  for(i = 0; i < MAX_QUEUES_PER_PORT; i++){
    printf("Enabling max shaping rate on port %d queue %d... ",DIFFPERF_EGRESS_PORT, i);
    status = bf_tm_sched_q_max_shaping_rate_enable(TOFINO_DEV_ID, DIFFPERF_EGRESS_PORT,i);
    print_bf_status(status);
  }
    printf("\n\n");
}


void set_buffer_pool_and_queue_sizes(){
  int i;
  int remaining_per_queue_size;

  printf("Setting App pool 0 size to %d cells... ", APP_POOL_0_SIZE);
  status = bf_tm_pool_size_set(TOFINO_DEV_ID, BF_TM_EG_APP_POOL_0,APP_POOL_0_SIZE);
  print_bf_status(status);

  printf("\n");

  remaining_per_queue_size = (int)(APP_POOL_0_SIZE - (2 * DIFFPERF_CURR_QUEUE_SIZE)) / (MAX_QUEUES_PER_PORT - 2);

  for(i = 0; i < 2; i++){
    printf("Setting size of Port %d Queue %d to static %d cells... ", DIFFPERF_EGRESS_PORT, i, DIFFPERF_CURR_QUEUE_SIZE);
    status = bf_tm_q_app_pool_usage_set(TOFINO_DEV_ID, DIFFPERF_EGRESS_PORT, i, 
  BF_TM_EG_APP_POOL_0, DIFFPERF_CURR_QUEUE_SIZE, BF_TM_Q_BAF_DISABLE, 0); // last param is hystersesis in cells. Set to zero (guessed!).
    print_bf_status(status);
  }

  for(i = 2; i < MAX_QUEUES_PER_PORT; i++){
    printf("Setting size of Port %d Queue %d to static %d cells... ", DIFFPERF_EGRESS_PORT, i, remaining_per_queue_size);
    status = bf_tm_q_app_pool_usage_set(TOFINO_DEV_ID, DIFFPERF_EGRESS_PORT, i, 
  BF_TM_EG_APP_POOL_0, remaining_per_queue_size, BF_TM_Q_BAF_DISABLE, 0); // last param is hystersesis in cells. Set to zero (guessed!).
    print_bf_status(status);
  }
}

bf_status_t setUpBfrt(bf_rt_target_t target, const char *progname)
{
  dev_tgt = target;
  // Get devMgr singleton instance
  auto &devMgr = bfrt::BfRtDevMgr::getInstance();
  // Get bfrtInfo object from dev_id and p4 program name
  auto bf_status = devMgr.bfRtInfoGet(dev_tgt.dev_id, progname, &bfrtInfo);
  // Creating a session object
  session = bfrt::BfRtSession::sessionCreate();
  printf("DiffPerf bfrt Setup!\n");
  return bf_status;
}

bf_status_t initRegisterAPI(void){

  // flow_bytes register
  // Table Object: Get a P4 table object (in this case the flow_bytes register table) and makes reg_flow_bytes points to it
  //status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.storeflowbytes.flow_bytes", &reg_flow_bytes);
  status = bfrtInfo->bfrtTableFromNameGet("SwitchEgressControl.apply_diffperf.flow_bytes", &reg_flow_bytes);
  assert(status == BF_SUCCESS); 

  //  Key field id
  status = reg_flow_bytes->keyFieldIdGet("$REGISTER_INDEX", &reg_flow_bytes_index);
  assert(status == BF_SUCCESS);

  // Data field id  
  status = reg_flow_bytes->dataFieldIdGet("SwitchEgressControl.apply_diffperf.flow_bytes.f1", &reg_flow_bytes_f1); // flow_bytes.f1 does not work
  assert(status == BF_SUCCESS);

/*
  bf_status = reg_flow_bytes_key->setValue(reg_flow_bytes_index, 0);
  if (bf_status != BF_SUCCESS)
    return bf_status;
*/
  printf("Initialized flow_bytes register APIs\n");
  return BF_SUCCESS;
}

/*  HELPER FUNCTIONS  */
double get_timediff_in_usec(struct timeval start, struct timeval end){
  
  double time_taken;
    
  time_taken = (end.tv_sec - start.tv_sec) * 1e6; 
  time_taken = (time_taken + (end.tv_usec - start.tv_usec));

  return time_taken;
}

//getRegiserValue
bf_status_t get_all_throughputs(){ 
/* Parameters of tableEntryGet
    [in]	session	Session Object
    [in]	dev_tgt	Device target
    [in]	key	Entry Key
    [in]	flag	Get Flags
    [out]	data	Entry Data   
  */

  int i, j,k, num_actually_read, index;
  struct timeval start, end;
  double bytes_diff, old_diff;
  double time_diff;
  

  gettimeofday(&start, NULL);
  //status = p4_pd_diffperf_register_range_read_flow_bytes(sess_hdl, p4_dev_tgt, 0, FLOW_REG_SIZE, REGISTER_READ_HW_SYNC, &num_actually_read, curr_flow_bytes, &array_size);
    
for(k=0; k < FLOW_REG_SIZE; k++){ 

    // Allocate a space for the key in the reg_flow_bytes table
    status = reg_flow_bytes->keyAllocate(&reg_flow_bytes_key);
    assert(status == BF_SUCCESS);

    // Allocate a space for the data in the reg_flow_bytes table
    status = reg_flow_bytes->dataAllocate(&reg_flow_bytes_data);
    assert(status == BF_SUCCESS);

    // Set the value of the key
    status = reg_flow_bytes_key->setValue(reg_flow_bytes_index, (uint64_t)k);
    assert(status == BF_SUCCESS);

    // get the flow index from the reg_flow_bytes_key table
    // get the flow value from the reg_flow_bytes_key table
    status = reg_flow_bytes->tableEntryGet(*session, dev_tgt, *(reg_flow_bytes_key.get()), hwflag, reg_flow_bytes_data.get());
    assert(status == BF_SUCCESS);

    std::vector<uint64_t> flow_bytes_val;
    status = reg_flow_bytes_data->getValue(reg_flow_bytes_f1, &flow_bytes_val);
    assert(status == BF_SUCCESS);

    curr_flow_bytes[k] = (uint32_t)flow_bytes_val[1]; // 0 is the pipeline number
    if (curr_flow_bytes[k]  > 0)
        printf("Flow id: %d and bytes are: %d\n", k,curr_flow_bytes[k]);

}

  gettimeofday(&end, NULL);

  if(status == BF_SUCCESS){
    printf("Time taken to read flow bytes: %d usec\n", (int)get_timediff_in_usec(start,end));
  }
  else {
    printf("Error reading register: %d\n", status);
    exit(1);
  }
  curr_time = end;

  if(first_bytes_read){
    memcpy(prev_flow_bytes, curr_flow_bytes, array_size);
    prev_time = curr_time;
    first_bytes_read = false;
  }
  else {
    time_diff = get_timediff_in_usec(prev_time, curr_time); // in usec
    printf("Time_diff is %d usec\n", (int)time_diff);
    
    for(i = 0; i < FLOW_REG_SIZE; i++){
      //index = 2*i + 1; // calculate the throughputs for pipe 1 only
      index = i; // calculate the throughputs for pipe 1 only
      bytes_diff = (double)curr_flow_bytes[index] - (double)prev_flow_bytes[index];
      if(bytes_diff < 0){
        old_diff = bytes_diff;
        bytes_diff = bytes_diff + UINT32_MAX;
        printf("NEGATIVE bytes_diff. Corrected: %f --> %f \n",old_diff,bytes_diff);
      }
      arr[i].flowThr = (bytes_diff / time_diff) * 8;// Mbits/sec
    }

    printf("The throughput values are:\n");
    for(j=0; j < FLOW_REG_SIZE; j++){
      printf("Flow %d: %f [(%d - %d)/ %f]\n", j, arr[j].flowThr, curr_flow_bytes[j], prev_flow_bytes[j], time_diff); 
    }
    memcpy(prev_flow_bytes, curr_flow_bytes, array_size * sizeof(uint32_t));
    prev_time = curr_time;
  }
  
  printf("\n");

return BF_SUCCESS;
}

void init_diffperf(){
  int i;
  char destAddr[16]; 

  for(i = 0; i < FLOW_REG_SIZE; i++){
    arr[i].flowId = i;
    strcpy(arr[i].srcIPAddr,"10.10.10.10");
    arr[i].flowQueue = 0;

    if(i == 0){
      strcpy(arr[i].destIPAddr, "10.10.10.1");
    }
    else if (i > 0 && i <=50){
      sprintf(destAddr,"10.10.10.%d", 20+i);
      strcpy(arr[i].destIPAddr, destAddr);
    }
    else if (i > 50){
      sprintf(destAddr,"10.10.10.%d", 20+i);
      strcpy(arr[i].destIPAddr, destAddr); 
    }
  }// end of for loop

}


double lookUpThroughput(int flowId){

  if(flowId == 0){
    // This should NEVER happen
    printf("ERROR: lookUpThroughput called with flowId 0\n");
    exit(1);
  }

  return arr[flowId].flowThr;

  /*
  Flow througputs: 0:20 1:30 2:40 
  throughput_values_from_dp: 0 20 0 30 0 40
  */
/*
  for (i = 0; i < MAX_ACTIVE_FLOWS ; i++){
    int fid = arr[i].flowId;
    if (fid == flowId){
      double thr = arr[i].flowThr;
      return thr;
    }     
  }
  */
} // End of lookUpThroughput method



void beta_Throughput_Fairness(){

  double meanBW = BW / MAX_ACTIVE_FLOWS;
  int flowId = 0;
  double flowThr = 0.0 ;
  double sum = 0.0;
  double mean = 0.0;
  double newMean = 0.0;
  double SD = 0.0;
  double z = 0.0;
  double newSum = 0.0;
  double sqrDiffMean = 0.0;
  double thrLessMean = 0.0;
  int nFlowsLessMean = 0;
  currentIndexShrRTT = 0;
  currentIndexLngRTT = 0;
  int i;

  longRTT = (int*) malloc(sizeof(int) * MAX_ACTIVE_FLOWS);
  for (i = 0; i < MAX_ACTIVE_FLOWS ; i++){
  longRTT[i] = -1;
  //printf("longRTT flow is %d \n",i);
  }


  shortRTT = (int*) malloc(sizeof(int) * MAX_ACTIVE_FLOWS);
  for (i = 0; i < MAX_ACTIVE_FLOWS ; i++){
  shortRTT[i] = -1;
  //printf("shortRTT flow is %d \n",i);
  }

for (i = 1; i <= MAX_ACTIVE_FLOWS ; i++){
    flowId = i;
    flowThr = lookUpThroughput(flowId);
    printf("flowId is %d. \t",flowId);
    printf("and its throughput is %1f. \n",flowThr);  
    sum += flowThr;
   }

  mean = sum / MAX_ACTIVE_FLOWS;

for (i = 1; i <= MAX_ACTIVE_FLOWS ; i++){
    flowThr = lookUpThroughput(i);
    newSum += ((flowThr - mean) * (flowThr - mean));
   }

  sqrDiffMean = newSum / MAX_ACTIVE_FLOWS;
  SD = sqrt(sqrDiffMean);
  z = mean - beta * SD;

printf("mean is %1f and standard deviation is %1f. \n",mean,SD);  


// classify


  for (i = 1; i <= MAX_ACTIVE_FLOWS ; i++){
  flowThr = lookUpThroughput(i);
  if (flowThr <= mean){
      thrLessMean += flowThr;
      nFlowsLessMean++;   
    }
   }  


  for (i = 1; i <= MAX_ACTIVE_FLOWS ; i++){
  flowId = i;
  flowThr = lookUpThroughput(flowId);
  if (flowThr <= z){
    longRTT[currentIndexLngRTT] = flowId;
    currentIndexLngRTT++;
    }
  else{
    shortRTT[currentIndexShrRTT] = flowId;
    currentIndexShrRTT++;
  }

  }
  printf("mean is %1f and nFlowsLessMean is %d \n",mean,nFlowsLessMean);  
  printf("z is %1f \n",z);  
  printf("currentIndexLngRTT is %d and currentIndexShrRTT is %d \n",currentIndexLngRTT,currentIndexShrRTT); 



// bandwidth allocation

  longRTTBW = (Gamma * ((thrLessMean / nFlowsLessMean) * currentIndexLngRTT)) + ((1 -Gamma) * (meanBW * currentIndexLngRTT));
  shortRTTBW = BW - longRTTBW;
  printf("LongRTT bandwidth is %f kbps and ShortRTT bandwidth is %1f kbps \n",longRTTBW,shortRTTBW);


  // implement 
  if(!TCP) {
    printf("UPDATE QUEUES WEIGHTS \n"); 
    printf("LongRTT Queue's weight is %f and ShortRTT Queue's weight is %1f  \n",longRTTBW,shortRTTBW); 
    //modify the associatiion of flows to the queue
   for (i = 0; i < currentIndexLngRTT ; i++){
    if (longRTT[i] != -1){
      printf("QUEUE_0 (longRTT): Flow id %d \n",longRTT[i]);
      arr[longRTT[i]].flowQueue = 0;  
    }
  }

   for (i = 0; i < currentIndexShrRTT ; i++){
    if (shortRTT[i] != -1){
      printf("QUEUE_1 (shortRTT): Flow id %d \n",shortRTT[i]);
      arr[shortRTT[i]].flowQueue = 1;
    }
   }

  } // end of implement 

} // End of beta_Throughput_Fairness method


//reverse hexadecimal number
void reverse(char* str) {
   int len = 2; char str1, str2;
   int r = strlen(str) - 2;
   while (len < r) {
      //swap(str[len++], str[r++]);
      str1 = str[len];
      str[len++] = str[r];
      str[r++] = str1;
      //swap(str[len++], str[r]);
      str2 = str[len];
      str[len++] = str[r];
      str[r] = str2;

      r = r - 3;
   }
}

bf_status_t perform_queue_allocation(){

printf("Entering Q allocation function\n");

  
  int i;
  for(i = 1; i <= MAX_ACTIVE_FLOWS; i++){
    // Table Object: Get a P4 table object (in this case the diffperf_set_queue table) and makes diffPerf_set_queue points to it
    status = bfrtInfo->bfrtTableFromNameGet("SwitchIngress.diffperf_set_queue", &diffPerf_set_queue);
    assert(status == BF_SUCCESS);


    /*bf_rt_id_t diffPerf_set_queue_src_addr;
    bf_rt_id_t diffPerf_set_queue_dst_addr;
    bf_rt_id_t diffPerf_set_queue_set_queue_id;
    bf_rt_id_t diffPerf_set_queue_q_id;
    */
    //Key field id
    status = diffPerf_set_queue->keyFieldIdGet("hdr.ipv4.src_addr", &diffPerf_set_queue_src_addr);
    assert(status == BF_SUCCESS);

    status = diffPerf_set_queue->keyFieldIdGet("hdr.ipv4.dst_addr", &diffPerf_set_queue_dst_addr);
    assert(status == BF_SUCCESS);

    status = diffPerf_set_queue->actionIdGet("SwitchIngress.set_queue_id", &diffPerf_set_queue_set_queue_id);
    assert(status == BF_SUCCESS);

    status = diffPerf_set_queue->dataFieldIdGet("q_id",diffPerf_set_queue_set_queue_id, &diffPerf_set_queue_q_id);
    assert(status == BF_SUCCESS);

    /*
    std::unique_ptr<bfrt::BfRtTableKey> diffPerf_set_queue_key;
    std::unique_ptr<bfrt::BfRtTableData> diffPerf_set_queue_data;
    */
    status = diffPerf_set_queue->keyAllocate(&diffPerf_set_queue_key);
    assert(status == BF_SUCCESS);
    status = diffPerf_set_queue->keyReset(diffPerf_set_queue_key.get());
    assert(status == BF_SUCCESS);

    status = diffPerf_set_queue->dataAllocate(&diffPerf_set_queue_data);
    assert(status == BF_SUCCESS);
    status = diffPerf_set_queue->dataReset(diffPerf_set_queue_set_queue_id, diffPerf_set_queue_data.get());
    assert(status == BF_SUCCESS);

   // convert IP from string to hexadecimal format
   //ip_srcAdd = inet_addr(arr[i].srcIPAddr);
   //ip_dstAdd = inet_addr(arr[i].destIPAddr);
   /*sprintf(str_src, "0x%08x", ip_srcAdd);
   sprintf(str_dst, "0x%08x", ip_dstAdd);
   reverse(str_src);
   reverse(str_dst);*/

    inet_pton(AF_INET, arr[i].srcIPAddr, &IP_Address); // convert string IP to binary
    IP_Address.addr = ntohl(IP_Address.addr); // convert IP from network byte order to host byte order
    status = diffPerf_set_queue_key -> setValue(diffPerf_set_queue_src_addr,static_cast<uint64_t>(IP_Address.addr));
    assert(status == BF_SUCCESS);

    inet_pton(AF_INET, arr[i].destIPAddr, &IP_Address);
    IP_Address.addr = ntohl(IP_Address.addr);
    status = diffPerf_set_queue_key -> setValue(diffPerf_set_queue_dst_addr,static_cast<uint64_t>(IP_Address.addr));
    assert(status == BF_SUCCESS);

    status = diffPerf_set_queue_data -> setValue(diffPerf_set_queue_q_id,static_cast<uint64_t>(arr[i].flowQueue));
    assert(status == BF_SUCCESS);

    status = diffPerf_set_queue->tableEntryMod(*session, dev_tgt, *diffPerf_set_queue_key, *diffPerf_set_queue_data);
    assert(status == BF_SUCCESS);

    printf("Flow %d (%d --> %d) assigned to queue %d. Status = %d\n", i, ip_srcAdd, ip_dstAdd, arr[i].flowQueue, status);

    }// end of for loop

  printf("Setting longRTTBW (queue %d) rate of %f... ",LONG_RTT_QUEUE_ID, longRTTBW);
  status = bf_tm_sched_q_shaping_rate_set(TOFINO_DEV_ID, DIFFPERF_EGRESS_PORT, LONG_RTT_QUEUE_ID, false, 4500, longRTTBW);
  print_bf_status(status);
  
  printf("Setting shortRTTBW (queue %d) rate of %f... ",SHORT_RTT_QUEUE_ID, shortRTTBW);
  status = bf_tm_sched_q_shaping_rate_set(TOFINO_DEV_ID, DIFFPERF_EGRESS_PORT, SHORT_RTT_QUEUE_ID, false, 4500, shortRTTBW);
  print_bf_status(status);

  return BF_SUCCESS;
}

void printFlowStatistics(){
  int i;
  char str[] = " ";

   double thr = 0.0;
   double avgThr = 0.0;
   for (i = 0; i < currentIndexLngRTT ; i++){
    if (longRTT[i] != -1){
      thr = lookUpThroughput(longRTT[i]);
      avgThr += thr;
      printf("QUEUE 0 (longRTT): Flow throughput %1f \n",thr);
      fprintf(fp, "%s %1f %s", "QUEUE 0: Flow throughput",thr,"\n");
    }
   }
    avgThr = avgThr / currentIndexLngRTT;
    fprintf(fp, "%s %1f %s", "QUEUE 0: Average throughput",avgThr,"\n");
    thr = 0.0;    
    avgThr = 0.0;

   for (i = 0; i < currentIndexShrRTT ; i++){
    if (shortRTT[i] != -1){
      // printf("ShortRTT flowID was NOT -1. It was: %d\n",shortRTT[i]); // DEBUG
      thr = lookUpThroughput(shortRTT[i]);
      avgThr += thr;  
      printf("QUEUE 1 (shortRTT): Flow throughput %1f \n",thr);  
      fprintf(fp, "%s %1f %s", "QUEUE 1: Flow throughput",thr,"\n");    
    }
  }
    avgThr = avgThr / currentIndexShrRTT;
    fprintf(fp, "%s %1f %s", "QUEUE 1: Average throughput",avgThr,"\n");

} // End of printFlowStatistics method


void run_diffperf(){

  printf("\n\n\n");
  printf("*****************************************************\n");
  // memset(throughput_values_from_dp, 0, FLOW_REG_SIZE * sizeof(double));
  get_all_throughputs(); // fills arr.flowThr
  beta_Throughput_Fairness();
  if (!TCP){
    perform_queue_allocation();
  } 
  printFlowStatistics();

  fprintf(fp,"----------------------------------------\n");
  fflush(fp);
  if(longRTT != NULL)
    free(longRTT);
  
  if(shortRTT != NULL)
    free(shortRTT);
}

int main (int argc, char **argv) {

    signal(SIGINT, interruptHandler);

    if(argc == 2){
        if(strcmp(argv[1],TCP_ALONE_STR) == 0){
        TCP = true;
        }
    }

    if(TCP){
        printf(YEL "------------- Running experiment for TCP Alone -------------\n" RESET);
    }
    else{
        printf(YEL "------------- Running experiment for DiffPerf -------------\n" RESET);
    }
    
    const char * p4progname = "diffperf_v16";
    init_bf_switchd(p4progname); //W: start P4Runtime server
    getSwitchName();
    init_tables(); // initialize tables and ports
    wait_for_port_link_up();
    //init_broadcast();  // create multicast for APP packet
    printf("--------------------------------------------------\n");
    enable_port_and_queue_rate_limiting();
    set_buffer_pool_and_queue_sizes();
    printf("--------------------------------------------------\n");
   
    printf("Starting diffPerf Switch..\n");
    // Prepare to program a table on  device 0
    memset(&dev_tgt, 0 , sizeof(dev_tgt));
    dev_tgt.dev_id = 0;
    dev_tgt.pipe_id = ALL_PIPES;

    // Setup bfrt runtime APIs and then the register APIs which will be used to read/write registers (reference)
    setUpBfrt(dev_tgt, p4progname);
    initRegisterAPI();

    printf("Starting DiffPerf Control Plane Unit ..\n");
    init_diffperf();
    printf("Press enter to continue...");
    getchar(); 
    printf("\n\n\n");
    fp = fopen("file.txt","w");
    // an infinite while loop is needed to keep the CP from exiting
    do {
            run_diffperf();
            sleep(10);

    } while (1); 


    //return 0;
}
