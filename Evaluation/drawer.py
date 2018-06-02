import pylab
import matplotlib.pyplot as plt
import math

def pro_data(x):
	y = float(x) * 1000000
	res = math.log(y)
	return res

def load_data(file_name):
	data_file = open(file_name, 'r')

	file_num = []
	exe_time = []

	for line in data_file:
		tmp = line.split(',')
		file_num.append(tmp[0])
		exe_time.append(tmp[1])

	return (file_num, exe_time)

def plot_data(X, Y, x_label, y_label):
	length = len(Y)

	pylab.figure(1)

	pylab.plot(X, Y, 'rx')
	pylab.xlabel(x_label)
	pylab.ylabel(y_label)

	pylab.show()

(sgx_e_file_num_1bytes, sgx_e_exe_time_1bytes) = load_data('./sgx_results/sgx_enc_results_1B.txt')
(sgx_e_file_num_1kbytes, sgx_e_exe_time_1kbytes) = load_data('./sgx_results/sgx_enc_results_1KB.txt')
(sgx_e_file_num_10kbytes, sgx_e_exe_time_10kbytes) = load_data('./sgx_results/sgx_enc_results_10KB.txt')

sgx_e_exe_time_1bytes_log = list(map(pro_data, sgx_e_exe_time_1bytes))
sgx_e_exe_time_1kbytes_log = list(map(pro_data, sgx_e_exe_time_1kbytes))
sgx_e_exe_time_10kbytes_log = list(map(pro_data, sgx_e_exe_time_10kbytes))


(sgx_d_file_num_1bytes, sgx_d_exe_time_1bytes) = load_data('./sgx_results/sgx_dec_results_1B.txt')
(sgx_d_file_num_1kbytes, sgx_d_exe_time_1kbytes) = load_data('./sgx_results/sgx_dec_results_1KB.txt')
(sgx_d_file_num_10kbytes, sgx_d_exe_time_10kbytes) = load_data('./sgx_results/sgx_dec_results_10KB.txt')

sgx_d_exe_time_1bytes_log = list(map(pro_data, sgx_d_exe_time_1bytes))
sgx_d_exe_time_1kbytes_log = list(map(pro_data, sgx_d_exe_time_1kbytes))
sgx_d_exe_time_10kbytes_log = list(map(pro_data, sgx_d_exe_time_10kbytes))



(e_file_num_1bytes, e_exe_time_1bytes) = load_data('./encryption_results/results_1byte.txt')
(e_file_num_1kbytes, e_exe_time_1kbytes) = load_data('./encryption_results/results_1kbytes.txt')
(e_file_num_10kbytes, e_exe_time_10kbytes) = load_data('./encryption_results/results_10kbytes.txt')

e_exe_time_1bytes_log = list(map(pro_data, e_exe_time_1bytes))
e_exe_time_1kbytes_log = list(map(pro_data, e_exe_time_1kbytes))
e_exe_time_10kbytes_log = list(map(pro_data, e_exe_time_10kbytes))



(e_bl_file_num_1bytes, e_bl_exe_time_1bytes) = load_data('./encryption_baseline_results/baseline_results_1byte.txt')
(e_bl_file_num_1kbytes, e_bl_exe_time_1kbytes) = load_data('./encryption_baseline_results/baseline_results_1kbytes.txt')
(e_bl_file_num_10kbytes, e_bl_exe_time_10kbytes) = load_data('./encryption_baseline_results/baseline_results_10kbytes.txt')

e_bl_exe_time_1bytes_log = list(map(pro_data, e_bl_exe_time_1bytes))
e_bl_exe_time_1kbytes_log = list(map(pro_data, e_bl_exe_time_1kbytes))
e_bl_exe_time_10kbytes_log = list(map(pro_data, e_bl_exe_time_10kbytes))



(file_num_1bytes, exe_time_1bytes) = load_data('./results/results_1bytes.txt')
(file_num_1kbytes, exe_time_1kbytes) = load_data('./results/results_1kbytes.txt')
(file_num_10kbytes, exe_time_10kbytes) = load_data('./results/results_10kbytes.txt')

exe_time_1bytes_log = list(map(pro_data, exe_time_1bytes))
exe_time_1kbytes_log = list(map(pro_data, exe_time_1kbytes))
exe_time_10kbytes_log = list(map(pro_data, exe_time_10kbytes))


(bl_file_num_1bytes, bl_exe_time_1bytes) = load_data('./baseline_results/baseline_results_1bytes.txt')
(bl_file_num_1kbytes, bl_exe_time_1kbytes) = load_data('./baseline_results/baseline_results_1kbytes.txt')
(bl_file_num_10kbytes, bl_exe_time_10kbytes) = load_data('./baseline_results/baseline_results_10kbytes.txt')

bl_exe_time_1bytes_log = list(map(pro_data, bl_exe_time_1bytes))
bl_exe_time_1kbytes_log = list(map(pro_data, bl_exe_time_1kbytes))
bl_exe_time_10kbytes_log = list(map(pro_data, bl_exe_time_10kbytes))

plt.figure(1)

# ax.plot(10, 0.2, 'g.', label='1 Byte')
# ax.legend(loc='upper left')


# line1 = plt.plot(file_num_1bytes, exe_time_1bytes, 'g.')
# plt.plot(bl_file_num_1bytes, bl_exe_time_1bytes, 'r.', file_num_1kbytes, exe_time_1kbytes, 'gs', bl_file_num_1kbytes, bl_exe_time_1kbytes, 'rs', file_num_10kbytes, exe_time_10kbytes, 'g^', bl_file_num_10kbytes, bl_exe_time_10kbytes, 'r^')
#
# axes.legend(line1, '1 Byte', loc='upper left')
plt.subplot(211)
# plt.xlabel('File Numbers')
plt.ylabel('Enc Execution Time (s)')
plt.axis([0, 110, 0, 0.0006])

# plt.scatter(e_file_num_1bytes, e_exe_time_1bytes_log, s=50, label='1 B', c='blue', marker='_', alpha=None, edgecolors='white')
#
# plt.scatter(e_bl_file_num_1bytes, e_bl_exe_time_1bytes_log, s=50, label='1 B (baseline)', c='red', marker='_', alpha=None, edgecolors='white')

plt.scatter(sgx_e_file_num_1bytes, sgx_e_exe_time_1bytes, s=50, label='1 B (sgx)', c='green', marker='_', alpha=None, edgecolors='white')

# plt.scatter(e_file_num_1kbytes, e_exe_time_1kbytes_log, s=50, label='1 KB', c='blue', marker='+', alpha=None, edgecolors='white')
#
# plt.scatter(e_bl_file_num_1kbytes, e_bl_exe_time_1kbytes_log, s=50, label='1 KB (baseline)', c='red', marker='+', alpha=None, edgecolors='white')

plt.scatter(sgx_e_file_num_1kbytes, sgx_e_exe_time_1kbytes, s=50, label='1 KB (sgx)', c='green', marker='+', alpha=None, edgecolors='white')


# plt.scatter(e_file_num_10kbytes, e_exe_time_10kbytes_log, s=50, label='10 KB', c='blue', marker='^', alpha=None, edgecolors='white')
#
# plt.scatter(e_bl_file_num_10kbytes, e_bl_exe_time_10kbytes_log, s=50, label='10 KB (baseline)', c='red', marker='^', alpha=None, edgecolors='white')

plt.scatter(sgx_e_file_num_10kbytes, sgx_e_exe_time_10kbytes, s=50, label='10 KB (sgx)', c='green', marker='^', alpha=None, edgecolors='white')

plt.legend(loc='upper left', fontsize='x-small')

plt.subplot(212)

plt.xlabel('File Numbers')
plt.ylabel('Dec Execution Time (s)')
plt.axis([0, 110, 0, 0.0030])

# plt.scatter(file_num_1bytes, exe_time_1bytes_log, s=50, label='1 B', c='blue', marker='_', alpha=None, edgecolors='white')
#
# plt.scatter(bl_file_num_1bytes, bl_exe_time_1bytes_log, s=50, label='1 B (baseline)', c='red', marker='_', alpha=None, edgecolors='white')

plt.scatter(sgx_d_file_num_1bytes, sgx_d_exe_time_1bytes, s=50, label='1 B (sgx)', c='green', marker='_', alpha=None, edgecolors='white')



# plt.scatter(file_num_1kbytes, exe_time_1kbytes_log, s=50, label='1 KB', c='blue', marker='+', alpha=None, edgecolors='white')
#
# plt.scatter(bl_file_num_1kbytes, bl_exe_time_1kbytes_log, s=50, label='1 KB (baseline)', c='red', marker='+', alpha=None, edgecolors='white')

plt.scatter(sgx_d_file_num_1kbytes, sgx_d_exe_time_1kbytes, s=50, label='1 KB (sgx)', c='green', marker='+', alpha=None, edgecolors='white')



# plt.scatter(file_num_10kbytes, exe_time_10kbytes_log, s=50, label='10 KB', c='blue', marker='^', alpha=None, edgecolors='white')
#
# plt.scatter(bl_file_num_10kbytes, bl_exe_time_10kbytes_log, s=50, label='10 KB (baseline)', c='red', marker='^', alpha=None, edgecolors='white')

plt.scatter(sgx_d_file_num_10kbytes, sgx_d_exe_time_10kbytes, s=50, label='10 KB (sgx)', c='green', marker='^', alpha=None, edgecolors='white')

# plt.legend(loc='upper left', fontsize='small')
plt.legend(loc='upper left', fontsize='x-small')

plt.show()
