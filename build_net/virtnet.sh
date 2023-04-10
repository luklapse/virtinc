#!/bin/bash

source topo.config

function create_images()
{
	docker build -t mycontainer:v1.3 .
}

function create_nodes(){
	echo "======================================"
	echo "create docker container here"
	
	#用于vscode远程登录容器终端，使用时需要修改容器中的相关文件
	port_cast=(8081 31 8082 32 8083 33)
	idx=0

	for h in ${nodes[@]}; do
		docker create --cap-add NET_ADMIN --name $h -p ${port_cast[$idx]}:${port_cast[$(($idx+1))]}  \
--mount type=bind,source=/root/Project/virtinct,target=/root/Project/virtinct --security-opt seccomp=unconfined mycontainer:v1.3
		idx=$(($idx+2))
		echo create $h
	done
}

function run_containers() 
{
	for h in ${nodes[@]}; do
		docker start $h
	done
}

function stop_containers()
{
	for h in ${nodes[@]}; do
		docker stop $h
	done
}

function destroy_containers()
{
	for h in ${nodes[@]}; do
		docker stop $h
		docker rm $h
	done
}

function destroy_images()
{
	docker rmi mycontainer:v1.3
}

function create_links(){
	echo "======================================"
	echo "create links"

	#创建/var/run/netns文件夹很可能很不存在
	mkdir /var/run/netns

	id=()
	for((i=0;i<3;i++));
	do
		id[$i]=$(sudo docker inspect -f '{{.State.Pid}}' ${nodes[$i]})
		ln -s /proc/${id[$i]}/ns/net /var/run/netns/${id[$i]}
	done

	id[3]=${id[1]}

 	total=${#links[*]}
	# A类地址
	ipAddr=("10.0.0.1/24" "10.0.0.2/24" "10.0.1.1/24" "10.0.1.2/24")
	idx=0

	for ((i=0; i<$total; i=i+4)) do
		echo ${links[$i]}, ${links[$i+1]}, ${links[$i+2]}, ${links[$i+3]}

		#ip link add * type veth peer name * 增设两个相互连接的网卡
		ip link add ${links[$i]}-${links[$i+1]} type veth peer name ${links[$i+2]}-${links[$i+3]}

		#1. ip link set  在网络内安装
		ip link set ${links[$i]}-${links[$i+1]} netns ${id[$idx]}
		#ip netns exec NAMESPACE COMMAND  在网络命名空间执行		 
		ip netns exec ${id[$idx]} ip link set ${links[$i]}-${links[$i+1]} up
		ip netns exec ${id[$idx]} ip addr add ${ipAddr[$idx]} dev ${links[$i]}-${links[$i+1]}
		#网卡设备增设ip 地址
		idx=$(($idx+1))

		#同上1
		ip link set ${links[$i+2]}-${links[$i+3]} netns ${id[$idx]}
		ip netns exec ${id[$idx]} ip link set ${links[$i+2]}-${links[$i+3]} up
		ip netns exec ${id[$idx]} ip addr add ${ipAddr[$idx]} dev ${links[$i+2]}-${links[$i+3]}
		idx=$(($idx+1))
	done
}


function destroy_links(){
	ip link del host1-iface1
	ip link del host2-iface1
	
	id=()
	for((i=0;i<3;i++));
	do
		id[$i]=$(sudo docker inspect -f '{{.State.Pid}}' ${nodes[$i]})
		ip netns del ${id[$i]}
	done
}

function ping_links(){
	#"10.0.0.2/24" 和 "10.0.1.2/24" 是switch的
	ipAddr=("10.0.0.1" "10.0.0.2" "10.0.1.1" "10.0.1.2")

	for((i=0;i<3;i++));
	do	
		id[$i]=$(sudo docker inspect -f '{{.State.Pid}}' ${nodes[$i]})
	done

	ip netns exec ${id[0]} ping ${ipAddr[1]}
	ip netns exec ${id[2]} ping ${ipAddr[3]}

	ip netns exec ${id[1]} ping ${ipAddr[0]}
	ip netns exec ${id[1]} ping ${ipAddr[2]}
}

#create_images
#create_nodes
#run_containers
create_links
ping_links


#destroy_links
#destroy_containers
#destroy_images