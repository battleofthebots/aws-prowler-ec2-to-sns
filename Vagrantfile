# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.define "prowlerrunner" do |prowlerrunner|
    prowlerrunner.vm.box = "generic/ubuntu2004"
    prowlerrunner.vm.box_check_update = false

    prowlerrunner.vm.provider "libvirt" do |vb|
        vb.memory = "2048"
        vb.cpus = 1
    end
  end

  config.vm.provision "ansible"  do |ansible|
    ansible.playbook = "./provisioning/playbook.yml"
   end
end