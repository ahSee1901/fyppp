import random
import numpy as np
import matplotlib.pyplot as plt

# 定义网络中的主机数量
NUM_HOSTS = 100

# 定义蠕虫攻击类
class WormAttackSimulator:
    def __init__(self, num_hosts, infection_rate):
        self.num_hosts = num_hosts
        self.infection_rate = infection_rate
        self.hosts = [0] * num_hosts  # 0 表示未感染，1 表示已感染
        self.hosts[0] = 1  # 假设第一个主机最初被感染
        
    def spread_worm(self):
        new_infections = []
        for i in range(self.num_hosts):
            if self.hosts[i] == 1:
                # 当前主机已感染，尝试感染其他主机
                for j in range(self.num_hosts):
                    if self.hosts[j] == 0 and random.random() < self.infection_rate:
                        new_infections.append(j)
        for index in new_infections:
            self.hosts[index] = 1
    
    def simulate(self, steps):
        infection_counts = []
        for _ in range(steps):
            self.spread_worm()
            infection_counts.append(sum(self.hosts))
        return infection_counts

# 定义蠕虫传播的参数
infection_rate = 0.1  # 感染率
simulation_steps = 50  # 模拟步骤

# 创建并运行蠕虫攻击模拟器
simulator = WormAttackSimulator(NUM_HOSTS, infection_rate)
infection_counts = simulator.simulate(simulation_steps)

# 将感染主机数量映射为流量数据（假设每个感染主机每秒产生固定数量的数据包）
worm_traffic = [count * 10 for count in infection_counts]

# 绘制感染主机数量随时间变化的图表
plt.plot(infection_counts, marker='o')
plt.title('Worm Infection Simulation')
plt.xlabel('Time Steps')
plt.ylabel('Number of Infected Hosts')
plt.grid(True)
plt.show()

# 定义 DoSAnomalyDetector 类
class DoSAnomalyDetector:
    def __init__(self, threshold):
        self.threshold = threshold
        self.traffic_data = []
        
    def update_traffic(self, packet_count):
        self.traffic_data.append(packet_count)
        
    def detect_anomaly(self):
        if len(self.traffic_data) == 0:
            return False
        
        mean_traffic = np.mean(self.traffic_data)
        std_dev_traffic = np.std(self.traffic_data)
        
        latest_traffic = self.traffic_data[-1]
        
        if (latest_traffic - mean_traffic) > self.threshold * std_dev_traffic:
            return True
        else:
            return False

# 初始化异常检测器
detector = DoSAnomalyDetector(threshold=3)

# 模拟正常流量数据（每秒的数据包数量）
normal_traffic = [100, 102, 98, 97, 100, 101, 99, 102, 98, 97]

# 引入DoS攻击（流量突然激增）
dos_attack_traffic = [1000, 1200, 1500]

# 合并正常流量、蠕虫攻击流量和DoS攻击流量
traffic_samples = normal_traffic + worm_traffic + dos_attack_traffic

# 在合并的流量数据中检测异常
anomaly_results = []
for packet_count in traffic_samples:
    detector.update_traffic(packet_count)
    if detector.detect_anomaly():
        anomaly_results.append(f"检测到异常流量: {packet_count}")
    else:
        anomaly_results.append(f"流量正常: {packet_count}")

# 显示结果
for result in anomaly_results:
    print(result)
