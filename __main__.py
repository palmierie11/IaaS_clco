"""An Azure RM Python Pulumi program"""

import pulumi
from pulumi_azure_native import resources, authorization, compute, storage, insights
import pulumi_azure_native as azure_native
import uuid
from pulumi_azure_native import authorization
#from pulumi_azuread import get_user
import pulumi_azuread as azuread
import pulumi_azure_native.insights as insights

config = pulumi.Config()
azure_location = config.get("azure-native:location") or "uksouth"

# Create an Azure Resource Group
resource_group = azure_native.resources.ResourceGroup("ResourceGroupIaaS",
    resource_group_name="ResourceGroupIaaS",)

# Create a Storage Account (there was no need at the beginning, but then required in boot settings)
sa = storage.StorageAccount('sa',
    resource_group_name=resource_group.name,
    sku={ "name": "Standard_LRS",},
    kind ="StorageV2",
)

# Create a Virtual Network
virtual_network = azure_native.network.VirtualNetwork("vnet",
    resource_group_name=resource_group.name,
    virtual_network_name="IaaS-vnet",
    address_space=azure_native.network.AddressSpaceArgs(
        address_prefixes=["10.0.0.0/16"],
    ),)

# Create a Subnet for VMs
subnet = azure_native.network.Subnet("subnet",
    resource_group_name=resource_group.name,
    virtual_network_name=virtual_network.name,
    subnet_name="IaaS-subnet",
    address_prefix="10.0.1.0/24",)

# Create a Network Security Group
network_security_group = azure_native.network.NetworkSecurityGroup("nsg",
    resource_group_name=resource_group.name,
    network_security_group_name="IaaS-nsg")

# Allow inbound traffic on port 80 (only http)
security_rule = azure_native.network.SecurityRule("InboundRule80",
    resource_group_name=resource_group.name,
    network_security_group_name=network_security_group.name,
    security_rule_name="Allow-80Inbound",
    priority=110,
    direction="Inbound",
    access="Allow",
    protocol="Tcp",
    source_port_range="*",
    destination_port_range="80",
    source_address_prefix="*",
    destination_address_prefix="*",)

# Create a Public IP Address for resources
public_ip = azure_native.network.PublicIPAddress("publicIP",
    resource_group_name=resource_group.name,
    public_ip_address_name="IaaS-PublicIP",
    sku=azure_native.network.PublicIPAddressSkuArgs(name="Standard"),
    public_ip_allocation_method="Static",
    zones=["1", "2", "3"],)

# Create a Load Balancer
load_balancer = azure_native.network.LoadBalancer("loadBalancer",
    resource_group_name=resource_group.name,
    load_balancer_name="IaaS-LoadBalancer",
    sku=azure_native.network.LoadBalancerSkuArgs(name="Standard"),
    frontend_ip_configurations=[azure_native.network.FrontendIPConfigurationArgs(
        name="FrontEnd",
        public_ip_address=azure_native.network.PublicIPAddressArgs(
            id=public_ip.id
        )
    )],
    backend_address_pools=[azure_native.network.BackendAddressPoolArgs(name="BackEndPool")],

    #to monitor port 80 of load balancer
    probes=[azure_native.network.ProbeArgs(
        name="httpProbe",
        protocol="Http",
        port=80,
        request_path="/",
        interval_in_seconds=15,
        number_of_probes=2
    )],
    load_balancing_rules=[azure_native.network.LoadBalancingRuleArgs(
        name="httpRule",
        frontend_ip_configuration=azure_native.network.SubResourceArgs(
            id=f"/subscriptions/f64c4fdf-b442-40de-87a2-e25c10cf426f/resourceGroups/ResourceGroupIaaS/providers/Microsoft.Network/loadBalancers/IaaS-LoadBalancer/frontendIPConfigurations/FrontEnd"
        ),
        backend_address_pool=azure_native.network.SubResourceArgs(
            id=f"/subscriptions/f64c4fdf-b442-40de-87a2-e25c10cf426f/resourceGroups/ResourceGroupIaaS/providers/Microsoft.Network/loadBalancers/IaaS-LoadBalancer/backendAddressPools/BackEndPool"
        ),
        probe=azure_native.network.SubResourceArgs(
            id=f"/subscriptions/f64c4fdf-b442-40de-87a2-e25c10cf426f/resourceGroups/ResourceGroupIaaS/providers/Microsoft.Network/loadBalancers/IaaS-LoadBalancer/probes/httpProbe"
        ),
        protocol="Tcp",
        frontend_port=80,
        backend_port=80,
        enable_floating_ip=False,
        idle_timeout_in_minutes=4,
        load_distribution="Default"
    )])


# Create Network Interfaces to connect VM1 to network
nic1 = azure_native.network.NetworkInterface("nic1",
    resource_group_name=resource_group.name,
    network_interface_name="IaaS-nic1",
    ip_configurations=[azure_native.network.NetworkInterfaceIPConfigurationArgs(
        name="ipconfig1",
        subnet=azure_native.network.SubnetArgs(id=subnet.id),
        private_ip_allocation_method="Dynamic",
        load_balancer_backend_address_pools=[azure_native.network.SubResourceArgs(
            id=load_balancer.backend_address_pools[0].id
        )]
    )],
    network_security_group=azure_native.network.NetworkSecurityGroupArgs(id=network_security_group.id))


# Create Network Interfaces for VM2
nic2 = azure_native.network.NetworkInterface("nic2",
    resource_group_name=resource_group.name,
    network_interface_name="IaaS-nic2",
    ip_configurations=[azure_native.network.NetworkInterfaceIPConfigurationArgs(
        name="ipconfig1",
        subnet=azure_native.network.SubnetArgs(id=subnet.id),
        private_ip_allocation_method="Dynamic",
        load_balancer_backend_address_pools=[azure_native.network.SubResourceArgs(
            id=load_balancer.backend_address_pools[0].id
        )]
    )],
    network_security_group=azure_native.network.NetworkSecurityGroupArgs(id=network_security_group.id))

# Create two managed disks
disk1 = compute.Disk(
    "disk1",
    resource_group_name=resource_group.name,
    disk_name = "IaaS-disk1",
    location=resource_group.location,
    sku={"name": " Standard_LRS"},
    creation_data={"create_option": compute.DiskCreateOption.EMPTY},
    disk_size_gb=1024
)

disk2 = compute.Disk(
    "disk2",
    resource_group_name=resource_group.name,
    disk_name="IaaS-disk2",
    location=resource_group.location,
    sku={"name": " Standard_LRS"},
    creation_data={"create_option": compute.DiskCreateOption.EMPTY},
    disk_size_gb=1024
)

# Create vm1
vm1 = azure_native.compute.VirtualMachine("vm1",
    resource_group_name=resource_group.name,
    vm_name="IaaS-vm1",
    network_profile=azure_native.compute.NetworkProfileArgs(
        network_interfaces=[azure_native.compute.NetworkInterfaceReferenceArgs(
            id=nic1.id
        )]
    ),
    hardware_profile=azure_native.compute.HardwareProfileArgs(vm_size="Standard_DS1_v2"),

    diagnostics_profile=azure_native.compute.DiagnosticsProfileArgs(
        boot_diagnostics=azure_native.compute.BootDiagnosticsArgs(
            enabled=True,
            storage_uri=sa.primary_endpoints.blob,
        ),
    ),
    storage_profile=azure_native.compute.StorageProfileArgs(
        os_disk=azure_native.compute.OSDiskArgs(create_option="FromImage"),
        image_reference=azure_native.compute.ImageReferenceArgs(
            publisher="Canonical",
            offer="0001-com-ubuntu-server-jammy",
            sku="22_04-lts",
            version="latest"
        ),
        data_disks=[azure_native.compute.DataDiskArgs(
            lun=0,
            create_option="Attach", #attaching an existing disk
            managed_disk=compute.ManagedDiskParametersArgs(id=disk1.id)
        )]
    ),
    os_profile=azure_native.compute.OSProfileArgs(
        computer_name="vm1",
        admin_username="azureuser",
        linux_configuration=azure_native.compute.LinuxConfigurationArgs(
            disable_password_authentication=True,
            ssh=azure_native.compute.SshConfigurationArgs(
                public_keys=[
                    azure_native.compute.SshPublicKeyArgs(
                        key_data="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDapReACokD9HQaAeV67yKWeifdGM+QKvduk8R8krDXbpgR1W/qMFCtps839sBbN9xle2qi/akF4l1Kb63DpLrlIIxtgGTPmKY4rAoxXgKkbo/xhyuJvaHxOzfU+YQ/O60eaTHLuTmg8DJezgK6CqbVUWCTvtFLe9kNiAsRR77NFKMyquepfdLo63jK2LlDxEpS4haAN+zMmB9Dz48AKRk8XDrM3fQBaBW3na2cu4C+Wxh1ZGHtsoR0XB2N99Aw3YpJfpw9xksR1xxzErgIXYmkmBmsLDA7liK+3gGip0foPd4NyPgr2dy+xg0YMZCZa34gd5uvyK1KLBJaxUlioiauK/ETKJTMI8lk9ujaQ88ahWsSvzq0u6wMQjk5YtTWNorptGQC7UfC5eEJMQ6ZYhK6/jLaO0ReCPMsKZz9UbsWyo+L9keFqX5Mvtk7ZvDIF/mR+EFZgaLIfVZNn5JQ+D7iN//a90QRO2107gQzkbknU0AF2zdSYVYKbUyLhNLp1G3vxQii+NWOu1/51CiLOOivYeFX2PD6cPIEaF0YP5WSHrKPhdYg6uBSrhbp02mWhxD98lXVpMrHxj72Y6XxsE+pwiyiHCIoPma65+g22yUCWx5f30SMWUuQ4RmKJD+v58EXPagqmPqZ7Qs+ONlOL3aZckZ3GsSwAsAzGckucjOnNQ== azureuser",
                        path="/home/azureuser/.ssh/authorized_keys",
    )],),),),)

vm1_extension = azure_native.compute.VirtualMachineExtension("vm1Extension",
    resource_group_name=resource_group.name,
    vm_name=vm1.name,
    vm_extension_name="installNginx",
    publisher="Microsoft.Azure.Extensions",
    type="CustomScript",
    type_handler_version="2.1",
    auto_upgrade_minor_version=True,
    settings={
        "commandToExecute": "sudo apt-get update && sudo apt-get install -y nginx && "
                            "echo '<head><title>vm1</title></head><body><h1>Web Portal</h1>"
                            "<p>vm1</p></body>' | sudo tee /var/www/html/index.nginx-debian.html && "
                            "sudo systemctl restart nginx"
    })

# Create vm2
vm2 = azure_native.compute.VirtualMachine("vm2",
    resource_group_name=resource_group.name,
    vm_name="IaaS-vm2",
    network_profile=azure_native.compute.NetworkProfileArgs(
        network_interfaces=[azure_native.compute.NetworkInterfaceReferenceArgs(
            id=nic2.id
        )]
    ),
    hardware_profile=azure_native.compute.HardwareProfileArgs(vm_size="Standard_DS1_v2"),
    diagnostics_profile=azure_native.compute.DiagnosticsProfileArgs(
        boot_diagnostics=azure_native.compute.BootDiagnosticsArgs(
            enabled=True,
            storage_uri=sa.primary_endpoints.blob,
        ),
    ),
    storage_profile=azure_native.compute.StorageProfileArgs(
        os_disk=azure_native.compute.OSDiskArgs(create_option="FromImage"),
        image_reference=azure_native.compute.ImageReferenceArgs(
            publisher="Canonical",
            offer="0001-com-ubuntu-server-jammy",
            sku="22_04-lts",
            version="latest"
        ),
        data_disks=[azure_native.compute.DataDiskArgs(
            lun=0,
            create_option="Attach",
            managed_disk=compute.ManagedDiskParametersArgs(id=disk2.id)
        )]
    ),
        os_profile=azure_native.compute.OSProfileArgs(
                computer_name="vm2",
                admin_username="azureuser",
                linux_configuration=azure_native.compute.LinuxConfigurationArgs(
                    disable_password_authentication=True,
                    ssh=azure_native.compute.SshConfigurationArgs(
                        public_keys=[
                            azure_native.compute.SshPublicKeyArgs(
                                key_data="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDapReACokD9HQaAeV67yKWeifdGM+QKvduk8R8krDXbpgR1W/qMFCtps839sBbN9xle2qi/akF4l1Kb63DpLrlIIxtgGTPmKY4rAoxXgKkbo/xhyuJvaHxOzfU+YQ/O60eaTHLuTmg8DJezgK6CqbVUWCTvtFLe9kNiAsRR77NFKMyquepfdLo63jK2LlDxEpS4haAN+zMmB9Dz48AKRk8XDrM3fQBaBW3na2cu4C+Wxh1ZGHtsoR0XB2N99Aw3YpJfpw9xksR1xxzErgIXYmkmBmsLDA7liK+3gGip0foPd4NyPgr2dy+xg0YMZCZa34gd5uvyK1KLBJaxUlioiauK/ETKJTMI8lk9ujaQ88ahWsSvzq0u6wMQjk5YtTWNorptGQC7UfC5eEJMQ6ZYhK6/jLaO0ReCPMsKZz9UbsWyo+L9keFqX5Mvtk7ZvDIF/mR+EFZgaLIfVZNn5JQ+D7iN//a90QRO2107gQzkbknU0AF2zdSYVYKbUyLhNLp1G3vxQii+NWOu1/51CiLOOivYeFX2PD6cPIEaF0YP5WSHrKPhdYg6uBSrhbp02mWhxD98lXVpMrHxj72Y6XxsE+pwiyiHCIoPma65+g22yUCWx5f30SMWUuQ4RmKJD+v58EXPagqmPqZ7Qs+ONlOL3aZckZ3GsSwAsAzGckucjOnNQ== azureuser",
                                path="/home/azureuser/.ssh/authorized_keys",
    )],),),),)

vm2_extension = azure_native.compute.VirtualMachineExtension("vm2Extension",
    resource_group_name=resource_group.name,
    vm_name=vm2.name,
    vm_extension_name="installNginx",
    publisher="Microsoft.Azure.Extensions",
    type="CustomScript",
    type_handler_version="2.1",
    auto_upgrade_minor_version=True,
    settings={
        "commandToExecute": "sudo apt-get update && sudo apt-get install -y nginx && "
                            "echo '<head><title>vm2</title></head><body><h1>Web Portal</h1>"
                            "<p>vm2</p></body>' | sudo tee /var/www/html/index.nginx-debian.html && "
                            "sudo systemctl restart nginx"
    })

# Create Action Group (for alert notifications)
actionGroup = insights.ActionGroup('actionGroup',
    resource_group_name=resource_group.name,
    action_group_name= 'IaaS-actionGroup',
    group_short_name='agshortname',
    enabled=True,
    email_receivers=[
        {
            "email_address": "wi24x502@technikum-wien.at",
            "name": "AdminEmail",
        }
    ],
)
# Create CPU Metric Alert for Both Machines
cpuMetricAlert = insights.MetricAlert('cpuMetricAlert',
    resource_group_name=resource_group.name,
    rule_name='MetricAlertOnMultipleResources',
    description='Alert when CPU usage exceeds 80% over a 5-minute period',
    severity=3,
    enabled=True,
    scopes=[vm1.id],
    window_size='PT5M',
    evaluation_frequency='PT1M',
    location="global",
    criteria=azure_native.insights.MetricAlertSingleResourceMultipleMetricCriteriaArgs(
            odata_type="Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
            all_of=[
                azure_native.insights.MetricCriteriaArgs(
                    name="HighCPUUsage",
                    metric_name="Percentage CPU",
                    metric_namespace="microsoft.compute/virtualmachines",
                    operator="GreaterThan",
                    threshold=80,
                    time_aggregation="Average",
                    dimensions=[],
                    criterion_type="StaticThresholdCriterion"
                )
            ]
        ),
        actions=[
            azure_native.insights.MetricAlertActionArgs(
                action_group_id=actionGroup.id
            )
        ] ,
        opts=pulumi.ResourceOptions(depends_on=[vm1])
)

cpuMetricAlert2 = insights.MetricAlert('cpuMetricAlert2',
    resource_group_name=resource_group.name,
    rule_name='MetricAlertOnMultipleResources_vm2',
    description='Alert when CPU usage exceeds 80% over a 5-minute period',
    severity=3,
    enabled=True,
    scopes=[vm2.id],
    window_size='PT5M',
    evaluation_frequency='PT1M',
    location="global",
    criteria=azure_native.insights.MetricAlertSingleResourceMultipleMetricCriteriaArgs(
            odata_type="Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
            all_of=[
                azure_native.insights.MetricCriteriaArgs(
                    name="HighCPUUsage",
                    metric_name="Percentage CPU",
                    metric_namespace="microsoft.compute/virtualmachines",
                    operator="GreaterThan",
                    threshold=80,
                    time_aggregation="Average",
                    dimensions=[],
                    criterion_type="StaticThresholdCriterion"
                )
            ]
        ),
        actions=[
            azure_native.insights.MetricAlertActionArgs(
                action_group_id=actionGroup.id
            )
        ] ,
        opts=pulumi.ResourceOptions(depends_on=[vm2])
)

# Log Analytics Workspace
log_analytics = azure_native.operationalinsights.Workspace(
    "logAnalyticsWorkspace",
    resource_group_name=resource_group.name,
    workspace_name="IaaSAnalyticsWorkspace",
    location=azure_location,
    sku=azure_native.operationalinsights.WorkspaceSkuArgs(name="PerGB2018"),
    retention_in_days=30,
)

activity_logs = insights.DiagnosticSetting(
    "activityLogDiagnostics",
    resource_uri=f"/subscriptions/f64c4fdf-b442-40de-87a2-e25c10cf426f",
    logs=[
        insights.LogSettingsArgs(
            category="Administrative",
            enabled=True,
            retention_policy=insights.RetentionPolicyArgs(enabled=True, days=30),
        ),
        insights.LogSettingsArgs(
            category="Security",
            enabled=True,
            retention_policy=insights.RetentionPolicyArgs(enabled=True, days=30),
        ),

    ],
     metrics=[],
    workspace_id=log_analytics.id,
)


# role assignment
email_nadia = "nagusentsova@edu.hse.ru"
email_stefan = "wi24b100@technikum-wien.at"
owner_role_id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # Owner Role
contributor_role_id = "b24988ac-6180-42a0-ab88-20f7382dd24c"  # Contributor Role
subscription_id = "f64c4fdf-b442-40de-87a2-e25c10cf426f"
resource_group_name = "ResourceGroupIaaS"

def assign_role(user_email, resource_group, role_name_suffix, role_definition_id):
    user = azuread.get_user(user_principal_name=user_email)  # Look up Azure AD user by email
    role_assignment_name = str(uuid.uuid4())  # Unique role assignment name
    return authorization.RoleAssignment(
        f"{role_name_suffix}RoleAssignment-{role_assignment_name}",
        scope=resource_group.id,
        role_assignment_name=role_assignment_name,
        principal_id=user.object_id,
        role_definition_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions/{role_definition_id}",
        principal_type="User",
        opts=pulumi.ResourceOptions(replace_on_changes=["role_assignment_name"]),
    )

 #Assign Owner Role to Nadia
assign_role(email_nadia, resource_group, "owner", owner_role_id)

# Assign Contributor Role to Stefan
#assign_role(email_stefan, resource_group, "contributor", contributor_role_id)

# Export the public IP address
pulumi.export("publicIP", public_ip.ip_address)


